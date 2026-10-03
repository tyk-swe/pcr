// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use super::Resource;
use crate::analysis::{Constraint, Error, serial::SERIAL_HALF};

const DEFAULT_MAX_FLOWS: usize = 8_192;
const DEFAULT_MAX_BYTES_PER_FLOW: usize = 1024 * 1024;
const DEFAULT_MAX_AGGREGATE_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_SEGMENTS_PER_FLOW: usize = 4_096;
const DEFAULT_IDLE_EXPIRY: Duration = Duration::from_secs(120);

/// Largest per-flow window the reassembler can order segments within.
pub const MAX_BYTES_PER_FLOW: usize = SERIAL_HALF as usize - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_flows: usize,
    /// Also the reordering window, so it may not exceed [`MAX_BYTES_PER_FLOW`].
    pub max_bytes_per_flow: usize,
    pub max_aggregate_bytes: usize,
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
    /// A zero limit refuses its resource entirely.
    pub fn validate(&self) -> Result<(), Error> {
        self.violation().map_or(Ok(()), |(field, value, reason)| {
            Err(Error::InvalidLimit {
                field: field.name(),
                value,
                reason,
            })
        })
    }

    pub(crate) fn violation(&self) -> Option<(Field, u64, Constraint)> {
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

    pub(super) fn flow_byte_error(&self) -> Resource {
        Resource::FlowByteLimit {
            limit: self.max_bytes_per_flow,
        }
    }

    pub(super) fn aggregate_byte_error(&self) -> Resource {
        Resource::AggregateByteLimit {
            limit: self.max_aggregate_bytes,
        }
    }
}

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
