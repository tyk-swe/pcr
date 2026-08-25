// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Finite ceilings for TLS session assembly.

use crate::analysis::Error;

/// Bytes one direction of one session may hold while its handshake is still
/// incomplete: one maximum handshake message plus the record framing around
/// it. A direction that would grow past this stops buffering and the session
/// is reported [`malformed`](super::Status::Malformed) rather than growing.
pub const MAX_DIRECTION_BUFFER: usize = 132 * 1024;

const DEFAULT_MAX_SESSIONS: usize = 8_192;
const DEFAULT_MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024;

/// Finite resource ceilings for one TLS session assembly pass.
///
/// A capture is untrusted input, so every buffer the collector keeps is
/// bounded twice: per direction by [`Limits::max_direction_bytes`], and across
/// the whole run by [`Limits::max_buffered_bytes`]. Sessions themselves are
/// bounded by [`Limits::max_sessions`], and the alert records one session
/// retains by [`MAX_ALERTS`](super::MAX_ALERTS). Reaching a ceiling degrades
/// the affected sessions to a status that says so and never fails the run.
/// Handshake bytes are charged against both byte ceilings before they are
/// buffered, and the retained alerts are charged as they are kept, so what a
/// run holds is bounded by `max_buffered_bytes` plus the alerts of the one
/// session that last added any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Conversations tracked at once. Reaching it retires the oldest tracked
    /// conversation, reporting an in-flight handshake as
    /// [`gap`](super::Status::Gap) and counting it in
    /// [`Summary::evicted_sessions`](super::Summary::evicted_sessions).
    pub max_sessions: usize,
    /// Handshake bytes buffered across every tracked conversation, including
    /// the alert records each one retained. Reaching it retires the oldest
    /// tracked conversations until the new bytes fit.
    pub max_buffered_bytes: usize,
    /// Handshake bytes buffered for one direction of one conversation.
    /// Defaults to [`MAX_DIRECTION_BUFFER`].
    pub max_direction_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
            max_direction_bytes: MAX_DIRECTION_BUFFER,
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
            ("max_direction_bytes", self.max_direction_bytes),
        ] {
            if value == 0 {
                return Err(Error::InvalidLimit {
                    field,
                    value: 0,
                    reason: "must be non-zero",
                });
            }
        }
        if self.max_direction_bytes > self.max_buffered_bytes {
            return Err(Error::InvalidLimit {
                field: "max_direction_bytes",
                value: u64::try_from(self.max_direction_bytes).unwrap_or(u64::MAX),
                reason: "cannot exceed max_buffered_bytes",
            });
        }
        Ok(())
    }
}
