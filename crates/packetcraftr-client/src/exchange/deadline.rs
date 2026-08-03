// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Absolute-deadline checks shared by exchange preparation and execution.

use std::time::Instant;

use packetcraftr_net::Error as LiveIoError;

use super::super::send::ClientError;

pub(crate) fn ensure_preparation_deadline(deadline: Instant) -> Result<(), ClientError> {
    if deadline.checked_duration_since(Instant::now()).is_none() {
        return Err(LiveIoError::DeadlineExceeded {
            operation: "preparing the exchange",
        }
        .into());
    }
    Ok(())
}
