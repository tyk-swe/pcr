// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::super::*;
use super::request::*;
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode {
    Offline,
    Live,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzCaseOutcome {
    Built,
    Rejected,
    Sent,
    Response,
    Timeout,
    Error,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzReproduction {
    pub operation_seed: u64,
    pub case_index: u64,
    pub case_seed: u64,
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
    pub reproduction: FuzzReproduction,
    pub shrink_values: Vec<FieldValue>,
    pub recipe: Packet,
    pub built: Option<BuiltPacket>,
    pub decoded: Option<DecodedPacket>,
    pub outcome: FuzzCaseOutcome,
    pub error: Option<FuzzCaseFailure>,
    pub sent: Option<Frame>,
    pub responses: Vec<Frame>,
    pub unmatched: Vec<Frame>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzStats {
    pub cases_generated: u64,
    pub cases_built: u64,
    pub cases_rejected: u64,
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: CaptureStatistics,
}

#[derive(Clone, Debug)]
pub struct FuzzResult {
    pub mode: FuzzMode,
    pub seed: u64,
    pub first_case: u64,
    pub cases: Vec<FuzzCase>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: FuzzStats,
}
