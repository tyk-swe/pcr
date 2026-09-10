// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Instant, UNIX_EPOCH};

use super::*;
use crate::probe::evidence::validate_response_frames_and_deadlines;
use crate::test_fixtures::RecordingClock;

#[derive(Default)]
struct Lifecycle {
    executed: Vec<Batch<()>>,
    processed: usize,
    late_response: bool,
}

impl ProbeLifecycle<Batch<()>> for Lifecycle {
    fn execute(&mut self, batch: &Batch<()>) -> Result<Execution, BoundaryError> {
        self.executed.push(batch.clone());
        let responses = if self.late_response && batch.sequence == 1 {
            vec![crate::exchange::Response {
                request_index: 0,
                response: crate::probe::test_fixtures::decoded_packet(
                    packetcraftr_core::packet::Packet::new(),
                    UNIX_EPOCH,
                    &[0x45],
                    Vec::new(),
                ),
                latency: Duration::from_millis(400),
            }]
        } else {
            Vec::new()
        };
        Ok(Execution {
            permit: batch.permit,
            sent: Vec::new(),
            responses,
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                elapsed: if batch.sequence == 0 {
                    Duration::from_millis(500)
                } else {
                    Duration::ZERO
                },
                ..Stats::default()
            },
        })
    }

    fn validate(&mut self, batch: &Batch<()>, execution: &Execution) -> Result<(), Error> {
        assert_eq!(Some(batch), self.executed.last());
        validate_response_frames_and_deadlines(
            &execution.responses,
            &execution.unsolicited,
            batch.timeout,
        )
        .map_err(|error| {
            Error::new(
                Workflow::Scan,
                ErrorKind::InvalidEvidence {
                    sequence: batch.sequence,
                    message: format!("{error:?}"),
                },
            )
        })
    }

    fn process(
        &mut self,
        batch: &Batch<()>,
        execution: Execution,
        _deadline: &Deadline,
    ) -> Result<ControlFlow<()>, Error> {
        assert_eq!(Some(batch), self.executed.last());
        assert_eq!(execution.permit, batch.permit);
        self.processed += 1;
        Ok(ControlFlow::Continue(()))
    }
}

fn deadline_with_spent(spent: Duration) -> Deadline {
    let now = Instant::now();
    let mut deadline = Deadline::with_time_source(Duration::from_secs(1), move || now);
    let _ = deadline.account(spent);
    deadline
}

fn batches() -> Vec<Batch<()>> {
    (0..2)
        .map(|sequence| Batch {
            probes: vec![()],
            timeout: Duration::from_millis(800),
            permit: crate::evidence::ExecutionPermit::new(),
            sequence,
        })
        .collect()
}

#[test]
fn child_timeout_accounts_for_prior_execution_and_pacing() {
    for workflow in [Workflow::Scan, Workflow::Traceroute] {
        let mut batches = batches();
        let mut lifecycle = Lifecycle::default();
        let mut clock = RecordingClock::default();
        let stats = run_batches(
            workflow,
            &mut batches,
            Some(5),
            &mut deadline_with_spent(Duration::ZERO),
            &mut clock,
            &mut lifecycle,
        )
        .expect("two bounded executions");

        assert_eq!(lifecycle.executed, batches);
        assert_eq!(batches[0].timeout, Duration::from_millis(800));
        assert_eq!(batches[1].timeout, Duration::from_millis(300));
        assert_eq!(lifecycle.processed, 2);
        assert_eq!(clock.delays, [Duration::from_millis(200)]);
        assert_eq!(stats.elapsed, Duration::from_millis(700));
    }
}

#[test]
fn zero_and_exhausted_operation_budgets_never_execute() {
    for spent in [Duration::from_secs(1), Duration::from_millis(1001)] {
        let mut lifecycle = Lifecycle::default();
        let error = run_batches(
            Workflow::Scan,
            batches(),
            None,
            &mut deadline_with_spent(spent),
            &mut RecordingClock::default(),
            &mut lifecycle,
        )
        .expect_err("no remaining execution budget");
        assert!(matches!(error.kind, ErrorKind::DurationLimit { .. }));
        assert!(lifecycle.executed.is_empty());
    }
}

#[test]
fn evidence_inside_original_timeout_but_outside_remaining_budget_is_rejected() {
    let mut lifecycle = Lifecycle {
        late_response: true,
        ..Lifecycle::default()
    };
    let error = run_batches(
        Workflow::Scan,
        batches(),
        Some(5),
        &mut deadline_with_spent(Duration::ZERO),
        &mut RecordingClock::default(),
        &mut lifecycle,
    )
    .expect_err("400 ms evidence exceeds the clipped 300 ms timeout");
    assert!(matches!(
        error.kind,
        ErrorKind::InvalidEvidence { sequence: 1, .. }
    ));
    assert_eq!(lifecycle.processed, 1);
}
