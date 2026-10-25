// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deadlines shared by workflows and their callers.

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::Error;

/// Allowance for a passive route or interface lookup whose operation has no deadline.
pub const PASSIVE_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// The boundary itself is expired: no time remains once nothing is left.
#[must_use]
pub(crate) fn expired(deadline: &Deadline) -> bool {
    !matches!(deadline.remaining(), Ok(remaining) if !remaining.is_zero())
}

pub(crate) fn ensure_preparation_deadline(deadline: &Deadline) -> Result<(), Error> {
    if expired(deadline) {
        return Err(Error::DeadlineExceeded {
            operation: "preparing the exchange",
        });
    }
    Ok(())
}
