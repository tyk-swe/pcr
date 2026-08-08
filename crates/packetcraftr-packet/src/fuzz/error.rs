// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use thiserror::Error;

use crate::budget::DeadlineExceeded;
use crate::error::{Classification, Classified, Kind};

use super::request::FuzzTarget;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FuzzError {
    #[error("invalid fuzz limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("fuzz strategies cannot be empty")]
    InvalidStrategies,
    #[error("fuzz case index arithmetic overflowed")]
    CaseIndexOverflow,
    #[error("fuzz duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("fuzz target {target} is invalid: {message}")]
    InvalidTarget { target: FuzzTarget, message: String },
    #[error("fuzz base packet is invalid: {message}")]
    InvalidBasePacket { message: String },
    #[error("packet has no field compatible with the selected fuzz strategies")]
    NoCompatibleTargets,
    #[error("fuzz retained/wire bytes {actual} exceed the configured limit of {limit}")]
    ByteLimit { actual: u64, limit: u64 },
    #[error("fuzz worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
}

impl Classified for FuzzError {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidStrategies
            | Self::CaseIndexOverflow
            | Self::InvalidDuration { .. }
            | Self::InvalidTarget { .. } => Classification::new(
                "cli.fuzz_limit",
                Kind::Cli,
                Some(
                    "use valid layer.field targets and finite non-zero case, byte, rate, timeout, evidence, and duration limits",
                ),
            ),
            Self::InvalidBasePacket { .. } => Classification::new(
                "packet.fuzz_recipe",
                Kind::Packet,
                Some(
                    "use a base packet within the configured layer, reflected-value, and target-field limits",
                ),
            ),
            Self::NoCompatibleTargets => Classification::new(
                "packet.fuzz_target",
                Kind::Packet,
                Some("select a strategy compatible with at least one reflective packet field"),
            ),
            Self::ByteLimit { .. } | Self::DurationLimit { .. } => Classification::new(
                "policy.fuzz_resource_limit",
                Kind::Policy,
                Some(
                    "reduce cases, packet sizes, timeout, or rate delay, or deliberately raise the finite fuzz limit",
                ),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        Vec::new()
    }
}

pub(super) fn duration_limit(error: DeadlineExceeded) -> FuzzError {
    FuzzError::DurationLimit {
        actual: error.actual,
        limit: error.limit,
    }
}
