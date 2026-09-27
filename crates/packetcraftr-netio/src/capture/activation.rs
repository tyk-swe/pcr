// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deadline-bounded activation and ownership of late native capture results.

use packetcraftr_core::{budget::Deadline, error::Source};

use super::{
    Limits, Session,
    live::{NativeCaptureParts, NativeCaptureSession},
};
use crate::{
    Error,
    workers::{
        Waited,
        reaper::{ReaperClient, ReaperStartError, shared_reaper},
    },
};

const OPERATION: &str = "arming capture";

pub(super) fn open(
    limits: Limits,
    deadline: &Deadline,
    activate: impl FnOnce() -> Result<NativeCaptureParts, Error> + Send + 'static,
) -> Result<Box<dyn Session>, Error> {
    open_with_reaper(limits, deadline, activate, shared_reaper)
}

fn open_with_reaper(
    limits: Limits,
    caller: &Deadline,
    activate: impl FnOnce() -> Result<NativeCaptureParts, Error> + Send + 'static,
    reaper: impl FnOnce() -> Result<ReaperClient, ReaperStartError>,
) -> Result<Box<dyn Session>, Error> {
    // Native activation spends wall time even when the caller's clock is frozen.
    let deadline = crate::deadline::detach(caller)
        .map_err(|interrupted| Error::interrupted(interrupted, OPERATION))?;
    let reaper = reaper().map_err(|error| Error::Capture {
        message: "native capture cleanup is unavailable".to_owned(),
        source: Some(Source::new(error)),
    })?;
    let permit = reaper.reserve().map_err(|error| Error::Capture {
        message: format!(
            "native capture activation capacity {} is exhausted",
            error.capacity
        ),
        source: Some(Source::new(error)),
    })?;
    let worker_deadline = deadline.clone();
    let mut task = permit
        .spawn(move || -> Result<Box<dyn Session>, Error> {
            crate::deadline::remaining(&worker_deadline)
                .map_err(|interrupted| Error::interrupted(interrupted, OPERATION))?;
            let parts = activate();
            // A late handle closes on this admitted worker without starting a
            // capture reader. A late native error must not mask interruption.
            crate::deadline::remaining(&worker_deadline)
                .map_err(|interrupted| Error::interrupted(interrupted, OPERATION))?;
            Ok(Box::new(NativeCaptureSession::spawn(parts?, limits)?))
        })
        .map_err(|error| Error::Capture {
            message: "could not start the native capture activation worker".to_owned(),
            source: Some(Source::new(error)),
        })?;
    task.wait_ready(&deadline);
    if let Err(interrupted) = crate::deadline::remaining(&deadline) {
        permit.retention_marker().mark_retained();
        reaper.transfer(Box::new(move || {
            // Keep admission through destruction of any unclaimed session.
            // Transfer even a just-finished result: its Drop may block.
            let _permit = permit;
            loop {
                match task.wait(&Deadline::new(crate::deadline::POLL_INTERVAL)) {
                    Waited::Finished(_) => break,
                    Waited::Pending(pending) => task = pending,
                }
            }
        }));
        return Err(Error::interrupted(interrupted, OPERATION));
    }
    task.try_take()
        .expect("activation finished before its deadline")
        .map_err(|_| Error::Capture {
            message: "native capture activation worker panicked".to_owned(),
            source: None,
        })?
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, mpsc},
        time::{Duration, Instant},
    };

    use packetcraftr_core::{budget::Cancellation, error::Classified, frame::LinkType};

    use super::*;
    use crate::{
        capture::{
            Metadata,
            live::{CaptureInterrupt, NativeCaptureEvent, NativeCaptureSource, NativeCaptureStats},
        },
        interface,
        workers::reaper::test_support::client_with_receiver,
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

    #[test]
    fn interrupted_activation_retains_admission_until_the_late_handle_closes() {
        let (reaper, cleanup) = client_with_receiver(1, 1);
        let worker_reaper = reaper.clone();
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(2)).with_cancellation(Some(signal.clone()));
        let (started, activating) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let (closing, closing_started) = mpsc::channel();
        let (close, closed) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            open_with_reaper(
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
                        metadata: Metadata {
                            interface: interface::Id {
                                name: "fixture0".to_owned(),
                                index: 7,
                            },
                            link_type: LinkType::ETHERNET,
                            snap_length: 64,
                            native: Default::default(),
                        },
                    })
                },
                || Ok(worker_reaper),
            )
        });
        activating.recv_timeout(Duration::from_secs(1)).unwrap();
        signal.cancel();
        assert_eq!(error_code(caller.join().unwrap()), "io.cancelled");
        assert!(
            reaper.reserve().is_err(),
            "blocked activation retains admission"
        );
        let cleanup = std::thread::spawn(cleanup.recv_timeout(Duration::from_secs(1)).unwrap());
        release.send(()).unwrap();
        closing_started
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert!(
            reaper.reserve().is_err(),
            "native destruction retains admission"
        );
        close.send(()).unwrap();
        cleanup.join().unwrap();
        assert!(reaper.reserve().is_ok(), "cleanup returns admission");
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
        let (reaper, _cleanup) = client_with_receiver(1, 1);
        let _occupied = reaper.reserve().unwrap();
        let result = open_with_reaper(
            Limits::default(),
            &Deadline::new(Duration::from_secs(1)),
            || panic!("an unadmitted activation must not run"),
            || Ok(reaper),
        );
        assert!(matches!(result, Err(Error::Capture { message, .. })
            if message == "native capture activation capacity 1 is exhausted"));
    }
}
