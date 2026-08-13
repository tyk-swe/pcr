// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::build::{DEFAULT_MAX_PACKET_SIZE, Options as BuildOptions};

use super::error::FuzzError;
use super::{
    DEFAULT_CASES, DEFAULT_MAX_CASES, DEFAULT_MAX_FIELD_BYTES, DEFAULT_MAX_LIST_ITEMS,
    DEFAULT_MAX_SHRINK_STEPS, DEFAULT_MAX_TOTAL_BYTES, MAX_CASES, MAX_DURATION, MAX_FIELD_BYTES,
    MAX_LIST_ITEMS, MAX_SHRINK_STEPS, MAX_STRATEGIES,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzStrategy {
    #[default]
    Boundary,
    Random,
    BitFlip,
    Malformed,
}

impl FuzzStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boundary => "boundary",
            Self::Random => "random",
            Self::BitFlip => "bit_flip",
            Self::Malformed => "malformed",
        }
    }
}

impl fmt::Display for FuzzStrategy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzTarget {
    pub layer: usize,
    pub field: String,
}

impl fmt::Display for FuzzTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.layer, self.field)
    }
}

impl FromStr for FuzzTarget {
    type Err = FuzzTargetParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (layer, field) = value
            .split_once('.')
            .ok_or_else(|| FuzzTargetParseError(value.to_owned()))?;
        let layer = layer
            .parse::<usize>()
            .map_err(|_| FuzzTargetParseError(value.to_owned()))?;
        if field.is_empty()
            || !field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(FuzzTargetParseError(value.to_owned()));
        }
        Ok(Self {
            layer,
            field: field.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("invalid fuzz target {0:?}; expected LAYER.FIELD")]
pub struct FuzzTargetParseError(String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzLimits {
    pub max_cases: usize,
    pub max_packet_bytes: usize,
    pub max_total_bytes: usize,
    pub max_field_bytes: usize,
    pub max_list_items: usize,
    pub max_shrink_steps: usize,
    pub max_duration: Duration,
}

impl Default for FuzzLimits {
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

impl FuzzLimits {
    pub fn validate(self) -> std::result::Result<Self, FuzzError> {
        for (field, value, maximum) in [
            ("max_cases", self.max_cases, MAX_CASES),
            (
                "max_packet_bytes",
                self.max_packet_bytes,
                DEFAULT_MAX_PACKET_SIZE,
            ),
            (
                "max_total_bytes",
                self.max_total_bytes,
                DEFAULT_MAX_TOTAL_BYTES,
            ),
            ("max_field_bytes", self.max_field_bytes, MAX_FIELD_BYTES),
            ("max_list_items", self.max_list_items, MAX_LIST_ITEMS),
            ("max_shrink_steps", self.max_shrink_steps, MAX_SHRINK_STEPS),
        ] {
            if value == 0 || value > maximum {
                return Err(FuzzError::InvalidLimit {
                    field,
                    value: value as u64,
                    reason: format!("must be within 1..={maximum}"),
                });
            }
        }
        if self.max_packet_bytes > self.max_total_bytes {
            return Err(FuzzError::InvalidLimit {
                field: "max_packet_bytes",
                value: self.max_packet_bytes as u64,
                reason: "cannot exceed max_total_bytes".to_owned(),
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_DURATION {
            return Err(FuzzError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_DURATION,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzRequest {
    pub seed: u64,
    pub first_case: u64,
    pub cases: usize,
    pub strategies: Vec<FuzzStrategy>,
    /// Empty means every reflectively readable field in layer/schema order.
    pub targets: Vec<FuzzTarget>,
    pub build: BuildOptions,
    pub limits: FuzzLimits,
}

impl Default for FuzzRequest {
    fn default() -> Self {
        Self {
            seed: 0,
            first_case: 0,
            cases: DEFAULT_CASES,
            strategies: vec![
                FuzzStrategy::Boundary,
                FuzzStrategy::Random,
                FuzzStrategy::BitFlip,
                FuzzStrategy::Malformed,
            ],
            targets: Vec::new(),
            build: BuildOptions::default(),
            limits: FuzzLimits::default(),
        }
    }
}

impl FuzzRequest {
    pub fn validate(&self) -> std::result::Result<(), FuzzError> {
        self.limits.validate()?;
        if self.cases == 0 || self.cases > self.limits.max_cases {
            return Err(FuzzError::InvalidLimit {
                field: "cases",
                value: self.cases as u64,
                reason: format!("must be within 1..={}", self.limits.max_cases),
            });
        }
        if self.strategies.is_empty() {
            return Err(FuzzError::InvalidStrategies);
        }
        if self.strategies.len() > MAX_STRATEGIES {
            return Err(FuzzError::InvalidLimit {
                field: "strategies",
                value: self.strategies.len() as u64,
                reason: format!("at most {MAX_STRATEGIES} strategies may be selected"),
            });
        }
        if self
            .strategies
            .iter()
            .enumerate()
            .any(|(index, strategy)| self.strategies[..index].contains(strategy))
        {
            return Err(FuzzError::InvalidStrategies);
        }
        let final_case_offset =
            u64::try_from(self.cases - 1).map_err(|_| FuzzError::CaseIndexOverflow)?;
        self.first_case
            .checked_add(final_case_offset)
            .ok_or(FuzzError::CaseIndexOverflow)?;
        if self.build.max_packet_size == 0
            || self.build.max_packet_size > self.limits.max_packet_bytes
        {
            return Err(FuzzError::InvalidLimit {
                field: "build.max_packet_size",
                value: self.build.max_packet_size as u64,
                reason: format!("must be within 1..={}", self.limits.max_packet_bytes),
            });
        }
        Ok(())
    }
}
