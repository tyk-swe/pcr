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
