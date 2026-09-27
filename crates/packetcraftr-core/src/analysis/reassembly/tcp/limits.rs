// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::analysis::{Constraint, Error};

const DEFAULT_MAX_FLOWS: usize = 8_192;
const DEFAULT_MAX_BYTES_PER_FLOW: usize = 1024 * 1024;
const DEFAULT_MAX_AGGREGATE_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_SEGMENTS_PER_FLOW: usize = 4_096;
const DEFAULT_IDLE_EXPIRY: Duration = Duration::from_secs(120);

/// Half the 32-bit TCP sequence space, the distance beyond which "before"
/// and "after" stop being distinguishable.
const SERIAL_HALF_SPACE: usize = 1usize << 31;

/// Largest per-flow window the reassembler can order segments within.
///
/// A window that reaches the serial half-space makes a retransmission and a
/// wrapped future segment indistinguishable, so the engine refuses to run
/// with one rather than mis-ordering a stream.
pub const MAX_BYTES_PER_FLOW: usize = SERIAL_HALF_SPACE.saturating_sub(1);

/// Every ceiling the TCP reassembler enforces.
///
/// The engine reads no ceiling outside this struct, so a caller that fills
/// every field has named every bound on the memory one reassembly run
/// retains. [`Reassembler::new`](super::Reassembler::new) accepts only limits
/// that [`Limits::validate`] accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum concurrently retained directional flows. A conversation
    /// occupies one per direction.
    pub max_flows: usize,
    /// Maximum retained bytes in one direction. This is also the reordering
    /// window, so it may not exceed [`MAX_BYTES_PER_FLOW`].
    pub max_bytes_per_flow: usize,
    /// Maximum retained payload and conservatively charged metadata across
    /// all flows.
    pub max_aggregate_bytes: usize,
    /// Maximum pending out-of-order segments retained for one flow.
    pub max_segments_per_flow: usize,
    /// Capture-time inactivity after which a flow is evicted.
    pub idle_expiry: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            max_bytes_per_flow: DEFAULT_MAX_BYTES_PER_FLOW,
            max_aggregate_bytes: DEFAULT_MAX_AGGREGATE_BYTES,
            max_segments_per_flow: DEFAULT_MAX_SEGMENTS_PER_FLOW,
            idle_expiry: DEFAULT_IDLE_EXPIRY,
        }
    }
}

impl Limits {
    /// Rejects a per-flow window above [`MAX_BYTES_PER_FLOW`] and an idle
    /// expiry the monotonic clock cannot represent. Every other value is
    /// honored as given; zero refuses that resource entirely.
    pub fn validate(&self) -> Result<(), Error> {
        self.violation().map_or(Ok(()), |(field, value, reason)| {
            Err(Error::InvalidLimit {
                field: field.name(),
                value,
                reason,
            })
        })
    }

    /// The first field [`validate`](Self::validate) refuses, so the offline
    /// pipeline can report it under its own field name.
    pub(crate) fn violation(&self) -> Option<(Field, u64, Constraint)> {
        // The per-flow window doubles as the reordering window, so a value
        // reaching the serial half-space makes a retransmission and a wrapped
        // future segment indistinguishable.
        if self.max_bytes_per_flow > MAX_BYTES_PER_FLOW {
            return Some((
                Field::MaxBytesPerFlow,
                u64::try_from(self.max_bytes_per_flow).unwrap_or(u64::MAX),
                Constraint::BelowSerialHalfSpace,
            ));
        }
        super::super::expiry::violation(self.idle_expiry)
            .map(|(value, reason)| (Field::IdleExpiry, value, reason))
    }
}

/// One [`Limits`] field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Field {
    MaxFlows,
    MaxBytesPerFlow,
    MaxAggregateBytes,
    MaxSegmentsPerFlow,
    IdleExpiry,
}

impl Field {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::MaxFlows => "max_flows",
            Self::MaxBytesPerFlow => "max_bytes_per_flow",
            Self::MaxAggregateBytes => "max_aggregate_bytes",
            Self::MaxSegmentsPerFlow => "max_segments_per_flow",
            Self::IdleExpiry => "idle_expiry",
        }
    }
}
