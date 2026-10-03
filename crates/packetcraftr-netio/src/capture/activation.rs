// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{
    Arc,
    mpsc::{self, Receiver, RecvTimeoutError},
};

use packetcraftr_core::{
    budget::{Deadline, Interrupted},
    error::Source,
};

use super::{
    ARMING, Limits, Session, admit,
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
        .map_err(|interrupted| Error::interrupted(interrupted, ARMING))?;
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
                admit(&worker_deadline, ARMING)?;
                let parts = activate();
                // A late native error must not mask interruption.
                admit(&worker_deadline, ARMING)?;
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

    match await_handoff(&claim, &deadline) {
        Err(interrupted) => {
            drop(claim);
            permit.retention_marker().mark_retained();
            reaper.transfer(Box::new(move || {
                let _permit = permit;
                wait_until_finished(task, POLL_INTERVAL, || {});
            }));
            Err(Error::interrupted(interrupted, ARMING))
        }
        Ok(Ok(started)) => {
            let retention = permit.retention_marker();
            let session = NativeCaptureSession::attach(started, task, permit, reaper.clone());
            if let Err(interrupted) = crate::deadline::remaining(&deadline) {
                retention.mark_retained();
                reaper.transfer(Box::new(move || drop(session)));
                return Err(Error::interrupted(interrupted, ARMING));
            }
            Ok(Box::new(session))
        }
        // Interruption still wins over a failure that arrived at the same moment.
        Ok(Err(error)) => {
            admit(&deadline, ARMING)?;
            Err(error)
        }
    }
}

fn await_handoff(
    claim: &Receiver<Result<Started, Error>>,
    deadline: &Deadline,
) -> Result<Result<Started, Error>, Interrupted> {
    // The channel signals the handoff, not cancellation, so the wait is sliced.
    loop {
        let remaining = crate::deadline::remaining(deadline)?;
        match claim.recv_timeout(remaining.min(POLL_INTERVAL)) {
            Ok(outcome) => return Ok(outcome),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Ok(Err(Error::Capture {
                    message: "native capture activation worker panicked".to_owned(),
                    source: None,
                }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(dead_code)]

    use std::{
        sync::{
            Arc,
            mpsc::{self, Sender},
        },
        time::{Duration, Instant},
    };

    use packetcraftr_core::{budget::Cancellation, error::Classified};

    use super::*;
    use crate::capture::live::{
        CaptureInterrupt, NativeCaptureEvent, NativeCaptureSource, NativeCaptureStats,
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
        let (finished, completed) = mpsc::channel();
        let frozen = Instant::now();
        let result = open(
            Limits::default(),
            &Deadline::with_time_source(Duration::from_millis(10), move || frozen),
            move || {
                let _ = blocked.recv_timeout(Duration::from_secs(5));
                let _ = finished.send(());
                Err(activation_error())
            },
        );
        assert_eq!(error_code(result), "io.deadline_exceeded");
        assert!(
            completed.try_recv().is_err(),
            "the deadline must stop waiting before activation completes"
        );
        drop(release);
    }

    #[test]
    fn cancellation_during_activation_interrupts_the_wait() {
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal.clone()));
        let (started, activating) = mpsc::channel();
        let (release, blocked) = mpsc::channel::<()>();
        let (finished, completed) = mpsc::channel();
        let cancel = std::thread::spawn(move || {
            activating.recv_timeout(Duration::from_secs(1)).unwrap();
            signal.cancel();
        });
        let result = open(Limits::default(), &deadline, move || {
            started.send(()).unwrap();
            let _ = blocked.recv_timeout(Duration::from_secs(5));
            let _ = finished.send(());
            Err(activation_error())
        });
        cancel.join().unwrap();
        assert_eq!(error_code(result), "io.cancelled");
        assert_eq!(completed.try_recv(), Err(mpsc::TryRecvError::Empty));
        drop(release);
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
}
