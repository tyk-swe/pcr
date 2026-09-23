// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Instant;

use super::*;
use crate::test_fixtures::RecordingClock;

/// Echoes each batch's bound permit with a fixed elapsed time and records
/// what the executor was handed.
#[derive(Default)]
struct Lifecycle {
    executed: Vec<Batch<()>>,
    processed: usize,
}

impl ProbeLifecycle<Batch<()>> for Lifecycle {
    fn execute(&mut self, batch: &Batch<()>) -> Result<Execution, BoundaryError> {
        self.executed.push(batch.clone());
        Ok(Execution {
            permit: batch.permit,
            sent: Vec::new(),
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                elapsed: Duration::from_millis(100),
                ..Stats::default()
            },
        })
    }

    fn validate(&mut self, _batch: &Batch<()>, _execution: &Execution) -> Result<(), Error> {
        Ok(())
    }

    fn process(
        &mut self,
        _batch: &Batch<()>,
        _execution: Execution,
        _deadline: &Deadline,
    ) -> Result<ControlFlow<()>, Error> {
        self.processed += 1;
        Ok(ControlFlow::Continue(()))
    }
}

#[test]
fn batches_are_paced_by_the_previous_batch_size_and_run_under_their_grant() {
    let planned_permit = crate::evidence::ExecutionPermit::new();
    let batches = [2, 1, 1]
        .into_iter()
        .zip(0..)
        .map(|(probes, sequence)| Batch {
            probes: vec![(); probes],
            timeout: Duration::from_millis(800),
            permit: planned_permit,
            sequence,
        });
    let now = Instant::now();
    let mut deadline = Deadline::with_time_source(Duration::from_secs(1), move || now);
    let mut clock = RecordingClock::default();
    let mut lifecycle = Lifecycle::default();

    let stats = run_batches(
        Workflow::Traceroute,
        batches,
        Some(5),
        &mut deadline,
        &mut clock,
        &mut lifecycle,
    )
    .expect("three bounded batches");

    assert_eq!(
        clock.delays,
        [Duration::from_millis(400), Duration::from_millis(200)]
    );
    assert_eq!(
        lifecycle
            .executed
            .iter()
            .map(|batch| batch.timeout)
            .collect::<Vec<_>>(),
        [800, 500, 200].map(Duration::from_millis)
    );
    let permits = lifecycle
        .executed
        .iter()
        .map(|batch| batch.permit)
        .collect::<Vec<_>>();
    assert!(!permits.contains(&planned_permit));
    assert!(permits[0] != permits[1] && permits[1] != permits[2]);
    assert_eq!(lifecycle.processed, 3);
    assert_eq!(stats.elapsed, Duration::from_millis(900));
}
