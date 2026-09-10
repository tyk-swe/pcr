// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Finite ceilings for TLS session assembly.

use crate::analysis::Error;

/// Logical bytes buffered in one direction while its handshake is still
/// incomplete: one maximum handshake message plus the record framing around
/// it. A direction that would grow past this stops buffering and the session
/// is reported [`malformed`](super::Status::Malformed) rather than growing.
pub const MAX_DIRECTION_BUFFER: usize = 132 * 1024;

const DEFAULT_MAX_SESSIONS: usize = 8_192;
const DEFAULT_MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024;

/// Finite resource ceilings for one TLS session assembly pass.
///
/// Pending handshake bytes are bounded per direction by [`MAX_DIRECTION_BUFFER`]
/// and across the run by [`Limits::max_buffered_bytes`]. Sessions themselves are
/// bounded by [`Limits::max_sessions`], and the alert records one session retains
/// by [`MAX_ALERTS`](super::MAX_ALERTS). Reaching a ceiling degrades the affected
/// sessions to a status that says so and never fails the run. Handshake bytes
/// are charged before buffering; alerts are charged as they are retained. The
/// logical buffering charge can exceed `max_buffered_bytes` by the alerts of
/// the one session that last added any, until the collector enforces the budget.
///
/// This charge excludes parsed hello summaries, buffer allocation capacity,
/// tracking metadata, and emitted results. Parser and session-count limits bound
/// retained summaries separately. These limits are not a total-memory or RSS cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Conversations tracked at once. Reaching it retires the oldest tracked
    /// conversation, reporting an in-flight handshake as
    /// [`gap`](super::Status::Gap) and counting it in
    /// [`Summary::evicted_sessions`](super::Summary::evicted_sessions).
    pub max_sessions: usize,
    /// Logical handshake-buffer lengths across every tracked conversation,
    /// including retained alert charges, but not parsed hello summaries or
    /// allocation capacity. Reaching it retires the oldest
    /// tracked conversations until the new bytes fit. Any positive library
    /// budget is valid, including deliberate small-budget experiments. The CLI
    /// requires at least `MAX_DIRECTION_BUFFER` so a single direction can fit.
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
    /// Rejects a budget that is zero or self-contradictory, before any input
    /// is read.
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value) in [
            ("max_sessions", self.max_sessions),
            ("max_buffered_bytes", self.max_buffered_bytes),
        ] {
            if value == 0 {
                return Err(Error::InvalidLimit {
                    field,
                    value: 0,
                    reason: "must be non-zero",
                });
            }
        }
        Ok(())
    }
}
