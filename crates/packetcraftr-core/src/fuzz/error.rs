// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use thiserror::Error;

use crate::error::{BoundaryError, Classification, Classified, Coordinate, Kind};

use super::request::Target;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] crate::budget::Cancelled),
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
    InvalidTarget { target: Target, message: String },
    #[error("invalid fuzz target {target:?}; expected LAYER.FIELD")]
    TargetSeparator { target: String },
    #[error("invalid fuzz target {target:?}; the layer must be a decimal index")]
    TargetLayer { target: String },
    #[error("invalid fuzz target {target:?}; the field must be a bounded reflective path")]
    TargetField {
        target: String,
        #[source]
        source: crate::field::Error,
    },
    #[error("fuzz base packet is invalid: {message}")]
    InvalidBasePacket { message: String },
    #[error("packet has no field compatible with the selected fuzz strategies")]
    NoCompatibleTargets,
    #[error("fuzz retained/wire bytes {actual} exceed the configured limit of {limit}")]
    ByteLimit { actual: u64, limit: u64 },
    #[error(
        "one fuzz value exceeds the retained/wire budget still unused under the configured limit of {limit} bytes"
    )]
    ValueTooLarge { limit: usize },
    #[error("fuzz worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("fuzz progressive output failed")]
    Output {
        #[source]
        source: BoundaryError,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
            Self::InvalidLimit { .. }
            | Self::InvalidStrategies
            | Self::CaseIndexOverflow
            | Self::InvalidDuration { .. }
            | Self::InvalidTarget { .. } => Classification::new(
                "cli.fuzz_limit",
                Kind::Usage,
                Some(
                    "use valid layer.field targets and finite non-zero case, byte, field, list, shrink, and duration limits",
                ),
            ),
            Self::TargetSeparator { .. } | Self::TargetLayer { .. } | Self::TargetField { .. } => {
                Classification::new(
                    "cli.fuzz_limit",
                    Kind::Usage,
                    Some(
                        "use LAYER.FIELD targets naming a layer index and a reflective field path",
                    ),
                )
            }
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
            Self::ByteLimit { .. } | Self::ValueTooLarge { .. } | Self::DurationLimit { .. } => {
                Classification::new(
                    "policy.fuzz_resource_limit",
                    Kind::Policy,
                    Some(
                        "reduce cases, packet sizes, timeout, or rate delay, or deliberately raise the finite fuzz limit",
                    ),
                )
            }
            Self::Output { source } => source.classification(),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Output { source } => source.context(),
            _ => None,
        }
    }

    /// The output variant delegates to its [`BoundaryError`], which carries a
    /// captured `causes` snapshot its own source chain no longer holds.
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Output { source } => source.as_causes(),
            error => crate::error::source_chain(error),
        }
    }
}

crate::budget::deadline_error_conversions!(Error);
