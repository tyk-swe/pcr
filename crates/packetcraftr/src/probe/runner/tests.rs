// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::probe::evidence::validate_response_frames_and_deadlines;
use crate::test_fixtures::RecordingClock;

#[derive(Default)]
struct RecordingExecutor {
    executed: Vec<Batch<()>>,
}

impl Executor<Batch<()>> for RecordingExecutor {
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
}

#[derive(Default)]
struct Lifecycle {
    processed: usize,
}

impl ProbeLifecycle<Batch<()>> for Lifecycle {
    fn validate(&mut self, batch: &Batch<()>, execution: &Execution) -> Result<(), Error> {
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
        _: &Batch<()>,
        _: Execution,
        _: &Deadline,
    ) -> Result<ControlFlow<()>, Error> {
        self.processed += 1;
        Ok(ControlFlow::Break(()))
    }
}

#[test]
fn batch_processing_can_end_the_operation_before_later_execution() {
    let mut executor = RecordingExecutor::default();
    let mut lifecycle = Lifecycle::default();
    let batches = (0..2)
        .map(|sequence| Batch {
            probes: vec![()],
            timeout: Duration::from_millis(500),
            permit: crate::evidence::ExecutionPermit::new(),
            sequence,
        })
        .collect::<Vec<_>>();
    let stats = run_batches(
        BatchRunOptions {
            workflow: Workflow::Scan,
            probes_per_second: None,
            evidence: EvidenceBounds {
                frames: 1,
                bytes: 10,
            },
        },
        batches,
        &mut Deadline::new(Duration::from_secs(2)),
        &mut RecordingClock::default(),
        &mut executor,
        &mut lifecycle,
    )
    .unwrap();
    assert_eq!(executor.executed.len(), 1);
    assert_eq!(lifecycle.processed, 1);
    assert_eq!(stats.elapsed, Duration::from_millis(100));
}
