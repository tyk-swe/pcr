// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::layout::DEFAULT_MAX_PACKET_SIZE;

use super::error::Error;
use super::{
    DEFAULT_CASES, DEFAULT_MAX_CASES, DEFAULT_MAX_FIELD_BYTES, DEFAULT_MAX_LIST_ITEMS,
    DEFAULT_MAX_SHRINK_STEPS, DEFAULT_MAX_TOTAL_BYTES, MAX_CASES, MAX_DURATION, MAX_FIELD_BYTES,
    MAX_LIST_ITEMS, MAX_PACKET_BYTES, MAX_SHRINK_STEPS, MAX_STRATEGIES, MAX_TOTAL_BYTES,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    #[default]
    Boundary,
    Random,
    BitFlip,
    Malformed,
}

impl Strategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boundary => "boundary",
            Self::Random => "random",
            Self::BitFlip => "bit_flip",
            Self::Malformed => "malformed",
        }
    }
}

display_via_as_str!(Strategy);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub layer: usize,
    pub field: String,
}

impl fmt::Display for Target {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.layer, self.field)
    }
}

impl FromStr for Target {
    type Err = TargetParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (layer, field) =
            value
                .split_once('.')
                .ok_or_else(|| TargetParseError::MissingSeparator {
                    target: value.to_owned(),
                })?;
        let layer = layer
            .parse::<usize>()
            .map_err(|_| TargetParseError::InvalidLayer {
                target: value.to_owned(),
            })?;
        if field.is_empty()
            || !field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(TargetParseError::InvalidField {
                target: value.to_owned(),
            });
        }
        Ok(Self {
            layer,
            field: field.to_owned(),
        })
    }
}

/// Why a `LAYER.FIELD` fuzz target text did not parse.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetParseError {
    #[error("invalid fuzz target {target:?}; expected LAYER.FIELD")]
    MissingSeparator { target: String },
    #[error("invalid fuzz target {target:?}; the layer must be a decimal index")]
    InvalidLayer { target: String },
    #[error("invalid fuzz target {target:?}; the field must be a non-empty [A-Za-z0-9_] name")]
    InvalidField { target: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_cases: usize,
    pub max_packet_bytes: usize,
    pub max_total_bytes: usize,
    pub max_field_bytes: usize,
    pub max_list_items: usize,
    pub max_shrink_steps: usize,
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_cases: DEFAULT_MAX_CASES,
            max_packet_bytes: DEFAULT_MAX_PACKET_SIZE,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_field_bytes: DEFAULT_MAX_FIELD_BYTES,
            max_list_items: DEFAULT_MAX_LIST_ITEMS,
            max_shrink_steps: DEFAULT_MAX_SHRINK_STEPS,
            max_duration: MAX_DURATION,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value, maximum) in [
            ("max_cases", self.max_cases, MAX_CASES),
            ("max_packet_bytes", self.max_packet_bytes, MAX_PACKET_BYTES),
            ("max_total_bytes", self.max_total_bytes, MAX_TOTAL_BYTES),
            ("max_field_bytes", self.max_field_bytes, MAX_FIELD_BYTES),
            ("max_list_items", self.max_list_items, MAX_LIST_ITEMS),
            ("max_shrink_steps", self.max_shrink_steps, MAX_SHRINK_STEPS),
        ] {
            if value == 0 || value > maximum {
                return Err(Error::InvalidLimit {
                    field,
                    value: u64::try_from(value).unwrap_or(u64::MAX),
                    reason: format!("must be within 1..={maximum}"),
                });
            }
        }
        if self.max_packet_bytes > self.max_total_bytes {
            return Err(Error::InvalidLimit {
                field: "max_packet_bytes",
                value: u64::try_from(self.max_packet_bytes).unwrap_or(u64::MAX),
                reason: "cannot exceed max_total_bytes".to_owned(),
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_DURATION {
            return Err(Error::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_DURATION,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub seed: u64,
    pub first_case: u64,
    pub cases: usize,
    pub strategies: Vec<Strategy>,
    /// Empty means every reflectively readable field in layer/schema order.
    pub targets: Vec<Target>,
    pub build: crate::build::Options,
    pub limits: Limits,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            seed: 0,
            first_case: 0,
            cases: DEFAULT_CASES,
            strategies: vec![
                Strategy::Boundary,
                Strategy::Random,
                Strategy::BitFlip,
                Strategy::Malformed,
            ],
            targets: Vec::new(),
            build: crate::build::Options::default(),
            limits: Limits::default(),
        }
    }
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if self.cases == 0 || self.cases > self.limits.max_cases {
            return Err(Error::InvalidLimit {
                field: "cases",
                value: self.cases as u64,
                reason: format!("must be within 1..={}", self.limits.max_cases),
            });
        }
        if self.strategies.is_empty() {
            return Err(Error::InvalidStrategies);
        }
        if self.strategies.len() > MAX_STRATEGIES {
            return Err(Error::InvalidLimit {
                field: "strategies",
                value: self.strategies.len() as u64,
                reason: format!("at most {MAX_STRATEGIES} strategies may be selected"),
            });
        }
        if self.strategies.iter().enumerate().any(|(index, strategy)| {
            self.strategies
                .get(..index)
                .is_some_and(|earlier| earlier.contains(strategy))
        }) {
            return Err(Error::InvalidStrategies);
        }
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "the `cases == 0` check above has already returned"
        )]
        let final_case_offset =
            u64::try_from(self.cases - 1).map_err(|_| Error::CaseIndexOverflow)?;
        self.first_case
            .checked_add(final_case_offset)
            .ok_or(Error::CaseIndexOverflow)?;
        if self.build.max_packet_size == 0
            || self.build.max_packet_size > self.limits.max_packet_bytes
        {
            return Err(Error::InvalidLimit {
                field: "build.max_packet_size",
                value: self.build.max_packet_size as u64,
                reason: format!("must be within 1..={}", self.limits.max_packet_bytes),
            });
        }
        Ok(())
    }
}
