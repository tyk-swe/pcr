// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use thiserror::Error;

use crate::error::{BoundaryError, Classification, Classified, Coordinate, Kind};

use super::request::Target;
use super::{MAX_STRATEGIES, MAX_TARGET_FIELDS};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] crate::budget::Cancelled),
    #[error("invalid fuzz limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: Constraint,
    },
    #[error("fuzz strategies cannot be empty")]
    InvalidStrategies,
    #[error("fuzz case index arithmetic overflowed")]
    CaseIndexOverflow,
    #[error("fuzz duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("fuzz target {target} is invalid: {reason}")]
    InvalidTarget { target: Target, reason: TargetFault },
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
    #[error("fuzz base packet is invalid: {reason}")]
    InvalidBasePacket { reason: BaseFault },
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

/// The rule an [`Error::InvalidLimit`] value breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Constraint {
    /// The value must be within `1..=maximum`.
    Within { maximum: u64 },
    /// The per-packet byte limit cannot exceed the total byte limit.
    AtMostMaxTotalBytes,
    /// At most [`MAX_STRATEGIES`] strategies may be selected.
    AtMostMaxStrategies,
}

impl std::fmt::Display for Constraint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Within { maximum } => write!(formatter, "must be within 1..={maximum}"),
            Self::AtMostMaxTotalBytes => formatter.write_str("cannot exceed max_total_bytes"),
            Self::AtMostMaxStrategies => {
                write!(
                    formatter,
                    "at most {MAX_STRATEGIES} strategies may be selected"
                )
            }
        }
    }
}

/// Why an [`Error::InvalidTarget`] cannot be resolved against the base packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetFault {
    /// The target's layer index is not below the packet's `layers`.
    LayerOutOfRange { layers: usize },
    /// The field path is not registered in the layer's schema.
    UnregisteredPath,
    /// The layer does not return a value for the field path.
    Unreadable,
}

impl std::fmt::Display for TargetFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LayerOutOfRange { layers } => {
                write!(formatter, "layer index is outside packet length {layers}")
            }
            Self::UnregisteredPath => formatter.write_str("unregistered reflective path"),
            Self::Unreadable => formatter.write_str("field is not reflectively readable"),
        }
    }
}

/// Why an [`Error::InvalidBasePacket`] cannot be fuzzed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BaseFault {
    /// The packet has more layers than the build's `max_layers`.
    Layers { layers: usize, max_layers: usize },
    /// Counting the packet's schema fields overflowed.
    FieldCountOverflow,
    /// The packet's schemas declare more than [`MAX_TARGET_FIELDS`] fields.
    SchemaFields { fields: usize },
    /// The packet reflects more than [`MAX_TARGET_FIELDS`] fields.
    ReflectedFields,
    /// The request selects more than [`MAX_TARGET_FIELDS`] targets.
    Targets { targets: usize },
}

impl std::fmt::Display for BaseFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Layers { layers, max_layers } => write!(
                formatter,
                "packet has {layers} layers, exceeding build.max_layers={max_layers}"
            ),
            Self::FieldCountOverflow => {
                formatter.write_str("reflected field-count arithmetic overflowed")
            }
            Self::SchemaFields { fields } => write!(
                formatter,
                "packet schema exposes {fields} fields, exceeding hard limit {MAX_TARGET_FIELDS}"
            ),
            Self::ReflectedFields => write!(
                formatter,
                "packet exposes more than {MAX_TARGET_FIELDS} reflected fields"
            ),
            Self::Targets { targets } => write!(
                formatter,
                "request selects {targets} fields, exceeding hard limit {MAX_TARGET_FIELDS}"
            ),
        }
    }
}
