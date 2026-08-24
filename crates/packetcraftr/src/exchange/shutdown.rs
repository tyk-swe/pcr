// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Panic-safe capture shutdown ownership.

use std::panic::{AssertUnwindSafe, catch_unwind};

use packetcraftr_netio::{Error as LiveIoError, capture::Session};

enum CaptureShutdownState {
    NotAttempted,
    Succeeded,
    Failed(LiveIoError),
}

pub(crate) struct CaptureGuard<C: Session> {
    pub(super) inner: C,
    shutdown_state: CaptureShutdownState,
}

impl<C: Session> CaptureGuard<C> {
    pub(crate) fn new(inner: C) -> Self {
        Self {
            inner,
            shutdown_state: CaptureShutdownState::NotAttempted,
        }
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), LiveIoError> {
        match &self.shutdown_state {
            CaptureShutdownState::Succeeded => return Ok(()),
            CaptureShutdownState::Failed(error) => return Err(error.clone()),
            CaptureShutdownState::NotAttempted => {}
        }

        // Mark completion before entering provider code so a panic cannot make
        // Drop invoke an unknown backend state a second time.
        self.shutdown_state = CaptureShutdownState::Succeeded;
        let result = match catch_unwind(AssertUnwindSafe(|| self.inner.shutdown())) {
            Ok(result) => result,
            Err(_) => Err(LiveIoError::Capture {
                message: "capture provider panicked during shutdown".to_owned(),
            }),
        };
        if let Err(error) = &result {
            self.shutdown_state = CaptureShutdownState::Failed(error.clone());
        }
        result
    }
}

impl<C: Session> Drop for CaptureGuard<C> {
    fn drop(&mut self) {
        if matches!(self.shutdown_state, CaptureShutdownState::NotAttempted) {
            let _ = self.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use packetcraftr_core::frame::LinkType;
    use packetcraftr_netio::capture::{Captured, Metadata, Statistics};
    use packetcraftr_netio::interface::Id as InterfaceId;

    use super::*;

    #[derive(Clone, Copy)]
    enum ShutdownOutcome {
        Success,
        Failure,
        Panic,
    }

    struct FixtureSession {
        metadata: Metadata,
        shutdown_calls: Arc<AtomicUsize>,
        outcome: ShutdownOutcome,
    }

    impl FixtureSession {
        fn new(shutdown_calls: Arc<AtomicUsize>, outcome: ShutdownOutcome) -> Self {
            Self {
                metadata: Metadata {
                    interface: InterfaceId {
                        name: "fixture0".to_owned(),
                        index: 7,
                    },
                    link_type: LinkType::ETHERNET,
                    snap_length: 1_500,
                },
                shutdown_calls,
                outcome,
            }
        }
    }

    impl Session for FixtureSession {
        fn metadata(&self) -> &Metadata {
            &self.metadata
        }

        fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
            Ok(())
        }

        fn next_captured_frame(
            &mut self,
            _timeout: Duration,
        ) -> Result<Option<Captured>, LiveIoError> {
            Ok(None)
        }

        fn shutdown(&mut self) -> Result<(), LiveIoError> {
            self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
            match self.outcome {
                ShutdownOutcome::Success => Ok(()),
                ShutdownOutcome::Failure => Err(LiveIoError::Capture {
                    message: "fixture shutdown failure".to_owned(),
                }),
                ShutdownOutcome::Panic => panic!("fixture shutdown panic"),
            }
        }

        fn statistics(&self) -> Statistics {
            Statistics::default()
        }
    }

    #[test]
    fn successful_shutdown_is_idempotent_and_drop_does_not_repeat_it() {
        let shutdown_calls = Arc::new(AtomicUsize::new(0));
        {
            let mut guard = CaptureGuard::new(FixtureSession::new(
                Arc::clone(&shutdown_calls),
                ShutdownOutcome::Success,
            ));
            guard.shutdown().expect("first shutdown");
            guard.shutdown().expect("cached successful shutdown");
        }

        assert_eq!(shutdown_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_shutdown_is_cached_and_drop_does_not_retry_unknown_backend_state() {
        let shutdown_calls = Arc::new(AtomicUsize::new(0));
        {
            let mut guard = CaptureGuard::new(FixtureSession::new(
                Arc::clone(&shutdown_calls),
                ShutdownOutcome::Failure,
            ));
            for _ in 0..2 {
                assert!(matches!(
                    guard.shutdown(),
                    Err(LiveIoError::Capture { message })
                        if message == "fixture shutdown failure"
                ));
            }
        }

        assert_eq!(shutdown_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn shutdown_panics_become_stable_capture_errors_without_a_second_provider_call() {
        let shutdown_calls = Arc::new(AtomicUsize::new(0));
        let mut guard = CaptureGuard::new(FixtureSession::new(
            Arc::clone(&shutdown_calls),
            ShutdownOutcome::Panic,
        ));

        for _ in 0..2 {
            assert!(matches!(
                guard.shutdown(),
                Err(LiveIoError::Capture { message })
                    if message == "capture provider panicked during shutdown"
            ));
        }
        assert_eq!(shutdown_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropping_an_open_guard_attempts_shutdown_exactly_once() {
        let shutdown_calls = Arc::new(AtomicUsize::new(0));
        drop(CaptureGuard::new(FixtureSession::new(
            Arc::clone(&shutdown_calls),
            ShutdownOutcome::Success,
        )));

        assert_eq!(shutdown_calls.load(Ordering::SeqCst), 1);
    }
}
