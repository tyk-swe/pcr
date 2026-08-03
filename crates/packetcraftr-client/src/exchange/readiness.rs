// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture readiness gate before the first packet is sent.

use std::time::Instant;

use packetcraftr_net::Error as LiveIoError;
use packetcraftr_net::capture::CaptureSession;

use super::transaction::ExchangeTransaction;

impl<C: CaptureSession> ExchangeTransaction<C> {
    pub(super) fn await_capture_readiness(&mut self) -> Result<(), LiveIoError> {
        let readiness_timeout = self.deadline.checked_duration_since(Instant::now()).ok_or(
            LiveIoError::DeadlineExceeded {
                operation: "waiting for capture readiness",
            },
        )?;
        self.capture.inner.wait_ready(readiness_timeout)
    }
}
