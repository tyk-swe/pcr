// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use packetcraftr::network as net;

use crate::errors::CliError;

pub(super) fn validate_capture_window(timeout: Duration) -> Result<(), CliError> {
    if timeout > net::capture::MAX_TIMEOUT || Instant::now().checked_add(timeout).is_none() {
        return Err(CliError::classified(net::Error::InvalidCaptureTimeout {
            timeout,
            maximum: net::capture::MAX_TIMEOUT,
        }));
    }
    Ok(())
}
