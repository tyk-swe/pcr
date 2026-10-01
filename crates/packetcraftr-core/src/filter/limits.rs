// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::Error;

pub const DEFAULT_MAX_FILTER_BYTES: usize = 64 * 1024;
pub const MAX_FILTER_NESTING: usize = 64;
pub const MAX_FILTER_TERMS: usize = 1024;
pub const MAX_FILTER_SET_MEMBERS: usize = 1024;

/// Ceilings on one display filter, applied while compiling it.
///
/// Every value is honored as given. `max_nesting`, `max_terms`, and
/// `max_set_members` also have stable maxima, which
/// [`validate`](Self::validate) enforces; `max_bytes` has none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_nesting: usize,
    pub max_terms: usize,
    pub max_set_members: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_FILTER_BYTES,
            max_nesting: MAX_FILTER_NESTING,
            max_terms: MAX_FILTER_TERMS,
            max_set_members: MAX_FILTER_SET_MEMBERS,
        }
    }
}

impl Limits {
    /// Checks the ceilings against their stable maxima.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidNestingLimit`], [`Error::InvalidTermLimit`], or
    /// [`Error::InvalidSetMemberLimit`] when the matching ceiling exceeds its
    /// stable maximum.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_nesting > MAX_FILTER_NESTING {
            return Err(Error::InvalidNestingLimit {
                value: self.max_nesting,
                maximum: MAX_FILTER_NESTING,
            });
        }
        if self.max_terms > MAX_FILTER_TERMS {
            return Err(Error::InvalidTermLimit {
                value: self.max_terms,
                maximum: MAX_FILTER_TERMS,
            });
        }
        if self.max_set_members > MAX_FILTER_SET_MEMBERS {
            return Err(Error::InvalidSetMemberLimit {
                value: self.max_set_members,
                maximum: MAX_FILTER_SET_MEMBERS,
            });
        }
        Ok(())
    }
}
