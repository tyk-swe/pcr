// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{
    Arc,
    mpsc::{self, RecvTimeoutError},
};

use packetcraftr_core::{budget::Deadline, error::Source};

use super::{
    Limits, Session,
    live::{NativeCaptureParts, NativeCaptureSession, Started},
};
use crate::{
    Error,
    deadline::POLL_INTERVAL,
    workers::{
        Class, Pool,
        reaper::{ReaperClient, ReaperStartError, shared_reaper, wait_until_finished},
    },
};

const OPERATION: &str = "arming capture";

pub(super) fn open(
    limits: Limits,
    deadline: &Deadline,
    activate: impl FnOnce() -> Result<NativeCaptureParts, Error> + Send + 'static,
) -> Result<Box<dyn Session>, Error> {
    open_with(
        limits,
        deadline,
        activate,
        crate::workers::shared(),
        shared_reaper,
    )
}

fn open_with(
    limits: Limits,
    caller: &Deadline,
    activate: impl FnOnce() -> Result<NativeCaptureParts, Error> + Send + 'static,
    pool: &Arc<Pool>,
    reaper: impl FnOnce() -> Result<ReaperClient, ReaperStartError>,
) -> Result<Box<dyn Session>, Error> {
    // Native activation spends wall time even when the caller's clock is frozen.
    let deadline = crate::deadline::detach(caller)
        .map_err(|interrupted| Error::interrupted(interrupted, OPERATION))?;
    // Both fallible cleanup-service steps happen before any native call.
    let reaper = reaper().map_err(|error| Error::Capture {
        message: "native capture cleanup is unavailable".to_owned(),
        source: Some(Source::new(error)),
    })?;
    let permit = pool.admit(Class::Native).map_err(|error| Error::Capture {
        message: format!(
            "native capture activation capacity {} is exhausted",
            error.capacity
        ),
        source: Some(Source::new(error)),
    })?;
    // A rendezvous: the reader starts only once an owner holds its stop flag.
    let (handoff, claim) = mpsc::sync_channel::<Result<Started, Error>>(0);
    let worker_deadline = deadline.clone();
    let task = permit
        .spawn(move || {
            let activated = (|| {
                crate::deadline::remaining(&worker_deadline)
                    .map_err(|interrupted| Error::interrupted(interrupted, OPERATION))?;
                let parts = activate();
                // A late native error must not mask interruption.
                crate::deadline::remaining(&worker_deadline)
                    .map_err(|interrupted| Error::interrupted(interrupted, OPERATION))?;
                parts
            })();
            match activated {
                Err(error) => {
                    let _ = handoff.send(Err(error));
                }
                Ok(parts) => {
                    let (started, reader) = NativeCaptureSession::prepare(parts, limits);
                    if handoff.send(Ok(started)).is_ok() {
                        reader.run();
                    }
                }
            }
        })
        .map_err(|error| Error::Capture {
            message: "could not start the native capture activation worker".to_owned(),
            source: Some(Source::new(error)),
        })?;

    // The channel signals the handoff, not cancellation, so the wait is sliced.
    let outcome = loop {
        match crate::deadline::remaining(&deadline) {
            Err(interrupted) => break Err(interrupted),
            Ok(remaining) => match claim.recv_timeout(remaining.min(POLL_INTERVAL)) {
                Ok(outcome) => break Ok(Some(outcome)),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break Ok(None),
            },
        }
    };
    match outcome {
        Err(interrupted) => {
            drop(claim);
            permit.retention_marker().mark_retained();
            reaper.transfer(Box::new(move || {
                let _permit = permit;
                wait_until_finished(task, POLL_INTERVAL, || {});
            }));
            Err(Error::interrupted(interrupted, OPERATION))
        }
        Ok(Some(Ok(started))) => {
            let retention = permit.retention_marker();
            let session = NativeCaptureSession::attach(started, task, permit, reaper.clone());
            if let Err(interrupted) = crate::deadline::remaining(&deadline) {
                retention.mark_retained();
                reaper.transfer(Box::new(move || drop(session)));
                return Err(Error::interrupted(interrupted, OPERATION));
            }
            Ok(Box::new(session))
        }
        // Interruption still wins over a failure that arrived at the same moment.
        Ok(failed) => {
            if let Err(interrupted) = crate::deadline::remaining(&deadline) {
                return Err(Error::interrupted(interrupted, OPERATION));
            }
            match failed {
                Some(Err(error)) => Err(error),
                None => Err(Error::Capture {
                    message: "native capture activation worker panicked".to_owned(),
                    source: None,
                }),
                Some(Ok(_)) => unreachable!("the session handoff is matched above"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc::{self, Sender},
        },
        thread,
        time::{Duration, Instant},
    };

    use packetcraftr_core::{budget::Cancellation, error::Classified};

    use super::*;
    use crate::{
        capture::live::{
            CaptureInterrupt, NativeCaptureEvent, NativeCaptureSource, NativeCaptureStats,
            test_support::BlockingSource,
        },
        test_support::capture_metadata,
        workers::reaper::test_support::{client_with_receiver, start_with},
    };

    fn activation_error() -> Error {
        Error::Capture {
            message: "injected activation failure".to_owned(),
            source: None,
        }
    }

    fn error_code(result: Result<Box<dyn Session>, Error>) -> &'static str {
        match result {
            Err(error) => error.classification().code,
            Ok(_) => panic!("activation should have been interrupted"),
        }
    }

    fn wait_for_slots(pool: &Arc<Pool>, active: usize) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while pool.snapshot().active != active {
            assert!(
                Instant::now() < deadline,
                "the pool never reached {active} active slots"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn stalled_activation_obeys_the_deadline_even_with_a_frozen_clock() {
        let (release, blocked) = mpsc::channel::<()>();
        let frozen = Instant::now();
        let result = open(
            Limits::default(),
            &Deadline::with_time_source(Duration::from_millis(10), move || frozen),
            move || {
                let _ = blocked.recv_timeout(Duration::from_millis(200));
                Err(activation_error())
            },
        );
        drop(release);
        assert_eq!(error_code(result), "io.deadline_exceeded");
        assert!(frozen.elapsed() < Duration::from_millis(150));
    }

    #[test]
    fn cancellation_during_activation_interrupts_the_wait() {
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal.clone()));
        let (started, activating) = mpsc::channel();
        let (release, blocked) = mpsc::channel::<()>();
        let cancel = std::thread::spawn(move || {
            activating.recv_timeout(Duration::from_secs(1)).unwrap();
            signal.cancel();
        });
        let began = Instant::now();
        let result = open(Limits::default(), &deadline, move || {
            started.send(()).unwrap();
            let _ = blocked.recv_timeout(Duration::from_millis(200));
            Err(activation_error())
        });
        drop(release);
        cancel.join().unwrap();
        assert_eq!(error_code(result), "io.cancelled");
        assert!(began.elapsed() < Duration::from_millis(150));
    }

    struct LateSource {
        closing: mpsc::Sender<()>,
        close: mpsc::Receiver<()>,
    }

    impl NativeCaptureSource for LateSource {
        fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
            panic!("a late activation must never start capture");
        }

        fn stats(&mut self) -> Result<NativeCaptureStats, Error> {
            panic!("a late activation must never start capture");
        }
    }

    impl Drop for LateSource {
        fn drop(&mut self) {
            let _ = self.closing.send(());
            let _ = self.close.recv_timeout(Duration::from_secs(1));
        }
    }

    struct NoInterrupt;

    impl CaptureInterrupt for NoInterrupt {
        fn interrupt(&self) {
            panic!("a late activation must never start capture");
        }
    }

    struct ReleasingInterrupt(Sender<()>);

    impl CaptureInterrupt for ReleasingInterrupt {
        fn interrupt(&self) {
            let _ = self.0.send(());
        }
    }

    #[test]
    fn interrupted_activation_retains_admission_until_the_late_handle_closes() {
        let pool = Arc::new(Pool::new(1, 1));
        let (reaper, cleanup) = client_with_receiver(1);
        let worker_reaper = reaper.clone();
        let worker_pool = Arc::clone(&pool);
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(2)).with_cancellation(Some(signal.clone()));
        let (started, activating) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let (closing, closing_started) = mpsc::channel();
        let (close, closed) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            open_with(
                Limits::default(),
                &deadline,
                move || {
                    started.send(()).unwrap();
                    blocked.recv_timeout(Duration::from_secs(1)).unwrap();
                    Ok(NativeCaptureParts {
                        source: Box::new(LateSource {
                            closing,
                            close: closed,
                        }),
                        interrupt: Arc::new(NoInterrupt),
                        metadata: capture_metadata("fixture0", 7),
                    })
                },
                &worker_pool,
                || Ok(worker_reaper),
            )
        });
        activating.recv_timeout(Duration::from_secs(1)).unwrap();
        signal.cancel();
        assert_eq!(error_code(caller.join().unwrap()), "io.cancelled");
        assert!(
            pool.admit(Class::Native).is_err(),
            "blocked activation retains admission"
        );
        let cleanup = std::thread::spawn(cleanup.recv_timeout(Duration::from_secs(1)).unwrap());
        release.send(()).unwrap();
        closing_started
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert!(
            pool.admit(Class::Native).is_err(),
            "native destruction retains admission"
        );
        close.send(()).unwrap();
        cleanup.join().unwrap();
        assert!(
            pool.admit(Class::Native).is_ok(),
            "cleanup returns admission"
        );
    }

    #[test]
    fn an_activation_error_arriving_with_expiry_reports_the_deadline() {
        let base = Instant::now();
        let caller = thread::current().id();
        let checks = AtomicUsize::new(0);
        // Expiry begins at the caller's fifth clock read.
        let clock = move || {
            if thread::current().id() == caller && checks.fetch_add(1, Ordering::SeqCst) >= 4 {
                base + Duration::from_secs(120)
            } else {
                base
            }
        };
        let pool = Arc::new(Pool::new(1, 1));
        let (reaper, _cleanup) = client_with_receiver(1);
        let result = open_with(
            Limits::default(),
            &Deadline::with_time_source(Duration::from_secs(60), clock),
            || Err(activation_error()),
            &pool,
            || Ok(reaper),
        );
        assert_eq!(error_code(result), "io.deadline_exceeded");
    }

    #[test]
    fn activation_preserves_native_errors_and_contains_panics() {
        let deadline = Deadline::new(Duration::from_secs(1));
        let native_error = open(Limits::default(), &deadline, || Err(activation_error()));
        assert!(matches!(native_error, Err(Error::Capture { message, .. })
            if message == "injected activation failure"));
        let panic = open(Limits::default(), &deadline, || panic!("injected panic"));
        assert!(matches!(panic, Err(Error::Capture { message, .. })
            if message == "native capture activation worker panicked"));
    }

    #[test]
    fn activation_cannot_start_without_admission() {
        let pool = Arc::new(Pool::new(1, 1));
        let (reaper, _cleanup) = client_with_receiver(1);
        let _occupied = pool.admit(Class::Native).unwrap();
        let result = open_with(
            Limits::default(),
            &Deadline::new(Duration::from_secs(1)),
            || panic!("an unadmitted activation must not run"),
            &pool,
            || Ok(reaper),
        );
        assert!(matches!(result, Err(Error::Capture { message, .. })
            if message == "native capture activation capacity 1 is exhausted"));
    }

    #[test]
    fn reaper_start_failure_does_not_start_an_unmanaged_activation() {
        let pool = Arc::new(Pool::new(1, 1));
        let reaper_error = match start_with(1, |_| {
            Err(std::io::Error::other("injected capture reaper failure"))
        }) {
            Ok(_) => panic!("injected reaper creation must fail"),
            Err(error) => error,
        };
        let result = open_with(
            Limits::default(),
            &Deadline::new(Duration::from_secs(1)),
            || panic!("activation must not run without cleanup"),
            &pool,
            || Err(reaper_error),
        );
        assert!(matches!(result, Err(Error::Capture { message, .. })
            if message == "native capture cleanup is unavailable"));
        assert_eq!(pool.snapshot().active, 0);
    }

    #[test]
    fn an_armed_source_holds_one_pool_slot_from_activation_through_its_reader() {
        let pool = Arc::new(Pool::new(1, 1));
        let (reaper, _cleanup) = client_with_receiver(1);
        let (reading, read_started) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let mut session = open_with(
            Limits::default(),
            &Deadline::new(Duration::from_secs(1)),
            move || {
                Ok(NativeCaptureParts {
                    source: Box::new(BlockingSource {
                        started: Some(reading),
                        release: released,
                        finished: None,
                    }),
                    interrupt: Arc::new(ReleasingInterrupt(release)),
                    metadata: capture_metadata("fixture0", 7),
                })
            },
            &pool,
            || Ok(reaper),
        )
        .expect("one source needs one slot");
        read_started
            .recv_timeout(Duration::from_secs(1))
            .expect("the reader runs on the activation's slot");
        assert_eq!(pool.snapshot().active, 1);
        assert!(
            pool.admit(Class::Native).is_err(),
            "the armed source holds exactly one slot"
        );
        session.shutdown().expect("the reader stops");
        drop(session);
        wait_for_slots(&pool, 0);
    }
}
