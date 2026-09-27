// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::analysis::{Constraint, Error};

/// One maximum handshake message plus record framing; exceeding it marks the session malformed.
pub const MAX_DIRECTION_BUFFER: usize = 132 * 1024;

const DEFAULT_MAX_SESSIONS: usize = 8_192;
const DEFAULT_MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024;

/// Reaching a ceiling degrades affected sessions to a status saying so; the run never fails.
/// These limits are not a total-memory or RSS ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Reaching it retires the oldest conversation; an in-flight handshake reports as a gap.
    pub max_sessions: usize,
    /// Reaching it retires the oldest tracked conversations until the new bytes fit.
    pub max_buffered_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value) in [
            ("max_sessions", self.max_sessions),
            ("max_buffered_bytes", self.max_buffered_bytes),
        ] {
            if value == 0 {
                return Err(Error::InvalidLimit {
                    field,
                    value: 0,
                    reason: Constraint::NonZero,
                });
            }
        }
        Ok(())
    }
}
