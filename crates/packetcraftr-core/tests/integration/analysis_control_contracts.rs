// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;
use packetcraftr_core::analysis::{
    Collector, CollectorNeeds, FrameRecord, Options, Session, Summary,
};
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::error::{BoundaryError, Classified};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

struct TerminalCollector {
    cancel_in_finish: Option<Cancellation>,
    finishes: Arc<AtomicUsize>,
}

impl Collector for TerminalCollector {
    type Event = usize;
    type Summary = ();

    fn needs(&self) -> CollectorNeeds {
        CollectorNeeds::default()
    }
    fn observe(&mut self, _: &FrameRecord<'_>) -> Result<Vec<usize>, BoundaryError> {
        Ok(Vec::new())
    }
    fn finish(self, _: &Summary) -> Result<(Vec<usize>, ()), BoundaryError> {
        self.finishes.fetch_add(1, Ordering::Relaxed);
        if let Some(cancellation) = self.cancel_in_finish {
            cancellation.cancel();
        }
        Ok((vec![1, 2, 3], ()))
    }
}

#[test]
fn cancellation_inside_finish_prevents_success_and_trailing_delivery() {
    let cancellation = Cancellation::default();
    let mut reader = common::reader(&[]);
    let mut delivered = Vec::new();
    let result = Session::new(
        common::registry(),
        Options {
            cancellation: Some(cancellation.clone()),
            ..Options::default()
        },
        TerminalCollector {
            cancel_in_finish: Some(cancellation),
            finishes: Arc::default(),
        },
    )
    .run(
        &mut reader,
        |_| Ok(()),
        |event| {
            delivered.push(event);
            Ok(())
        },
    );
    assert_eq!(
        result
            .err()
            .expect("cancelled finalizer must fail")
            .classification()
            .code,
        "io.cancelled"
    );
    assert!(delivered.is_empty());
}

#[test]
fn cancellation_inside_first_terminal_event_stops_drain() {
    let cancellation = Cancellation::default();
    let mut reader = common::reader(&[]);
    let mut delivered = Vec::new();
    let result = Session::new(
        common::registry(),
        Options {
            cancellation: Some(cancellation.clone()),
            ..Options::default()
        },
        TerminalCollector {
            cancel_in_finish: None,
            finishes: Arc::default(),
        },
    )
    .run(
        &mut reader,
        |_| Ok(()),
        |event| {
            delivered.push(event);
            cancellation.cancel();
            Ok(())
        },
    );
    assert_eq!(
        result
            .err()
            .expect("cancelled event drain must fail")
            .classification()
            .code,
        "io.cancelled"
    );
    assert_eq!(delivered, [1]);
}

#[test]
fn pass_retains_inherited_reader_deadline() {
    let now = Arc::new(std::sync::Mutex::new(Instant::now()));
    let source = now.clone();
    let inherited = Arc::new(Deadline::with_time_source(
        Duration::from_secs(1),
        move || *source.lock().unwrap(),
    ));
    let finishes = Arc::new(AtomicUsize::new(0));
    let mut reader = common::reader(&[]).with_deadline(inherited.clone());
    let mut sink = |_| Ok(());
    let pass = Session::new(
        common::registry(),
        Options::default(),
        TerminalCollector {
            cancel_in_finish: None,
            finishes: finishes.clone(),
        },
    )
    .observe(&mut reader, |_| Ok(()), &mut sink)
    .unwrap();
    *now.lock().unwrap() += Duration::from_secs(2);
    assert_eq!(
        pass.finish(&mut sink)
            .err()
            .expect("expired reader ceiling must survive observe")
            .classification()
            .code,
        "policy.duration_limit"
    );
    assert_eq!(finishes.load(Ordering::Relaxed), 0);
}

#[test]
fn pass_retains_separate_reader_cancellation_after_observe() {
    let signal = Cancellation::default();
    let mut reader = common::reader(&[]).with_cancellation(signal.clone());
    let finishes = Arc::new(AtomicUsize::new(0));
    let mut sink = |_| Ok(());
    let pass = Session::new(
        common::registry(),
        Options::default(),
        TerminalCollector {
            cancel_in_finish: None,
            finishes: finishes.clone(),
        },
    )
    .observe(&mut reader, |_| Ok(()), &mut sink)
    .unwrap();
    signal.cancel();
    assert_eq!(
        pass.finish(&mut sink)
            .err()
            .expect("reader cancellation survives observation")
            .classification()
            .code,
        "io.cancelled"
    );
    assert_eq!(finishes.load(Ordering::Relaxed), 0);
}

#[test]
fn selected_absent_empty_run_still_finishes_and_sink_errors_release_collector() {
    let finishes = Arc::new(AtomicUsize::new(0));
    let mut sink = |_| Ok(());
    let pass = Session::new(
        common::registry(),
        Options {
            stream: Some(packetcraftr_core::analysis::StreamRef {
                transport: packetcraftr_core::analysis::StreamTransport::Tcp,
                index: 7,
            }),
            ..Options::default()
        },
        TerminalCollector {
            cancel_in_finish: None,
            finishes: finishes.clone(),
        },
    )
    .observe(&mut common::reader(&[]), |_| Ok(()), &mut sink)
    .unwrap();
    assert!(pass.selected_absent());
    let mut count = 0;
    let result = pass.finish(&mut |_| {
        count += 1;
        Err(BoundaryError::internal_execution(
            "controlled output refusal",
            "test.output",
            "test",
        ))
    });
    assert_eq!(result.err().unwrap().classification().code, "test.output");
    assert_eq!(count, 1);
    assert_eq!(finishes.load(Ordering::Relaxed), 1);
    assert_eq!(Arc::strong_count(&finishes), 1);
}

#[test]
fn expired_caller_control_prevents_even_empty_finalization() {
    let now = Instant::now();
    let ticks = Arc::new(AtomicUsize::new(0));
    let source = ticks.clone();
    let deadline = Arc::new(Deadline::with_time_source(
        Duration::from_secs(1),
        move || now + Duration::from_secs(source.load(Ordering::Acquire) as u64),
    ));
    ticks.store(2, Ordering::Release);
    let finishes = Arc::new(AtomicUsize::new(0));
    let result = Session::new(
        common::registry(),
        Options {
            deadline: Some(deadline),
            ..Options::default()
        },
        TerminalCollector {
            cancel_in_finish: None,
            finishes: finishes.clone(),
        },
    )
    .run(&mut common::reader(&[]), |_| Ok(()), |_| Ok(()));
    assert_eq!(
        result.err().unwrap().classification().code,
        "policy.duration_limit"
    );
    assert_eq!(finishes.load(Ordering::Relaxed), 0);
    assert_eq!(Arc::strong_count(&finishes), 1);
}

#[test]
fn reader_control_is_restored_after_observation_cancellation() {
    struct CancellingCollector(Cancellation);
    impl Collector for CancellingCollector {
        type Event = ();
        type Summary = ();
        fn needs(&self) -> CollectorNeeds {
            CollectorNeeds::default()
        }
        fn observe(&mut self, _: &FrameRecord<'_>) -> Result<Vec<()>, BoundaryError> {
            self.0.cancel();
            Ok(Vec::new())
        }
        fn finish(self, _: &Summary) -> Result<(Vec<()>, ()), BoundaryError> {
            panic!("cancelled observation must not finalize")
        }
    }
    let registry = common::registry();
    let frame = common::tcp_frame(
        &registry,
        std::time::UNIX_EPOCH,
        common::client_tcp(1, 1, 16, 8192),
        &[],
    );
    let mut reader = common::reader(&[frame.clone(), frame])
        .with_deadline(Arc::new(Deadline::new(Duration::from_secs(60))));
    let cancellation = Cancellation::default();
    let result = Session::new(
        registry,
        Options {
            cancellation: Some(cancellation.clone()),
            ..Options::default()
        },
        CancellingCollector(cancellation),
    )
    .run(&mut reader, |_| Ok(()), |_| Ok(()));
    assert_eq!(result.err().unwrap().classification().code, "io.cancelled");
    assert!(
        reader
            .next_frame()
            .expect("the original reader control remains live")
            .is_some()
    );
}
