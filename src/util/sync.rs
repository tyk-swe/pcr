// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{LockResult, PoisonError};

/// Extension trait for LockResult to easily handle poisoned locks by ignoring the poison.
pub(crate) trait LockResultExt<Guard> {
    /// Returns the guard, ignoring whether the lock is poisoned or not.
    ///
    /// This is equivalent to `unwrap_or_else(PoisonError::into_inner)`.
    fn ignore_poison(self) -> Guard;
}

impl<Guard> LockResultExt<Guard> for LockResult<Guard> {
    fn ignore_poison(self) -> Guard {
        self.unwrap_or_else(PoisonError::into_inner)
    }
}
