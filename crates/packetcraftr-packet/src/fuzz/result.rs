// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Classification, Classified};
use crate::{
    Packet, build::BuiltPacket, decode::DecodedPacket, diagnostic::Diagnostic, field::FieldValue,
};

use super::request::FuzzStrategy;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode {
    Offline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzCaseOutcome {
    Built,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzMutation {
    pub layer: usize,
    pub protocol: String,
    pub field: String,
    pub strategy: FuzzStrategy,
    pub original: FieldValue,
    pub value: FieldValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzCaseFailure {
    message: String,
    classification: Classification,
    causes: Vec<String>,
}

impl FuzzCaseFailure {
    pub fn new(
        message: impl Into<String>,
        classification: Classification,
        causes: Vec<String>,
    ) -> Self {
        Self {
            message: message.into(),
            classification,
            causes,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for FuzzCaseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Classified for FuzzCaseFailure {
    fn classification(&self) -> Classification {
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

#[derive(Clone, Debug)]
pub struct FuzzCase {
    pub index: u64,
    pub seed: u64,
    pub mutation: FuzzMutation,
    pub shrink_values: Vec<FieldValue>,
    pub recipe: Packet,
    pub built: Option<BuiltPacket>,
    pub decoded: Option<DecodedPacket>,
    pub outcome: FuzzCaseOutcome,
    pub error: Option<FuzzCaseFailure>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzStats {
    pub cases_generated: u64,
    pub cases_built: u64,
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
}

#[derive(Clone, Debug)]
pub struct FuzzResult {
    pub seed: u64,
    pub first_case: u64,
    pub cases: Vec<FuzzCase>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: FuzzStats,
}
