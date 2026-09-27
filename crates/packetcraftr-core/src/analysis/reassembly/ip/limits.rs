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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_datagrams: usize,
    pub max_fragments_per_datagram: usize,
    pub max_bytes_per_datagram: usize,
    pub max_aggregate_bytes: usize,
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
        super::super::expiry::violation(self.idle_expiry)
            .map(|(value, reason)| (Field::IdleExpiry, value, reason))
    }
}

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
