// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::analysis::{Constraint, Error};

const DEFAULT_MAX_DATAGRAMS: usize = 8_192;
const DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM: usize = 256;
const DEFAULT_MAX_BYTES_PER_DATAGRAM: usize = 65_535;
const DEFAULT_MAX_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_RETAINED_OUTCOMES: usize = 8_192;
const DEFAULT_IDLE_EXPIRY: Duration = Duration::from_secs(30);

/// Every ceiling the IP reassembler enforces.
///
/// The engine reads no ceiling outside this struct, so a caller that fills
/// every field has named every bound on the memory one reassembly run
/// retains. [`Reassembler::new`](super::Reassembler::new) accepts only limits
/// that [`Limits::validate`] accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum concurrently retained IPv4 and IPv6 datagrams.
    pub max_datagrams: usize,
    /// Maximum physical fragments admitted to one retained datagram.
    pub max_fragments_per_datagram: usize,
    /// Maximum fragmentable payload extent retained for one datagram.
    pub max_bytes_per_datagram: usize,
    /// Maximum retained payload, reconstruction bytes, and conservatively
    /// charged metadata across all datagrams.
    pub max_aggregate_bytes: usize,
    /// Maximum per-datagram outcomes one expiry sweep may name.
    pub max_retained_outcomes: usize,
    /// Capture-time inactivity after which an incomplete datagram expires.
    pub idle_expiry: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_datagrams: DEFAULT_MAX_DATAGRAMS,
            max_fragments_per_datagram: DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM,
            max_bytes_per_datagram: DEFAULT_MAX_BYTES_PER_DATAGRAM,
            max_aggregate_bytes: DEFAULT_MAX_AGGREGATE_BYTES,
            max_retained_outcomes: DEFAULT_MAX_RETAINED_OUTCOMES,
            idle_expiry: DEFAULT_IDLE_EXPIRY,
        }
    }
}

impl Limits {
    /// Rejects an idle expiry the monotonic clock cannot represent. Every
    /// other value is honored as given; zero refuses that resource entirely.
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
        super::super::expiry::violation(self.idle_expiry)
            .map(|(value, reason)| (Field::IdleExpiry, value, reason))
    }
}

/// One [`Limits`] field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Field {
    MaxDatagrams,
    MaxFragmentsPerDatagram,
    MaxBytesPerDatagram,
    MaxAggregateBytes,
    MaxRetainedOutcomes,
    IdleExpiry,
}

impl Field {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::MaxDatagrams => "max_datagrams",
            Self::MaxFragmentsPerDatagram => "max_fragments_per_datagram",
            Self::MaxBytesPerDatagram => "max_bytes_per_datagram",
            Self::MaxAggregateBytes => "max_aggregate_bytes",
            Self::MaxRetainedOutcomes => "max_retained_outcomes",
            Self::IdleExpiry => "idle_expiry",
        }
    }
}
