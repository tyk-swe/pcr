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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_live_deadline_is_not_expired_and_preparation_proceeds() {
        let deadline = Deadline::new(Duration::from_secs(60));
        assert!(!expired(&deadline));
        assert!(ensure_preparation_deadline(&deadline).is_ok());
    }

    #[test]
    fn spent_deadlines_are_expired_and_stop_preparation() {
        for deadline in [Deadline::new(Duration::ZERO), Deadline::immediate(None)] {
            assert!(expired(&deadline));
            assert!(matches!(
                ensure_preparation_deadline(&deadline),
                Err(Error::DeadlineExceeded {
                    operation: "preparing the exchange"
                })
            ));
        }
    }
}
