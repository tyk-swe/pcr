// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Classification, Classified};
use crate::{
    Packet, build::BuiltPacket, decode::DecodedPacket, diagnostic::Diagnostic, field::FieldValue,
};

use super::request::Strategy;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOutcome {
    Built,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Mutation {
    pub layer: usize,
    pub protocol: String,
    pub field: String,
    pub strategy: Strategy,
    pub original: FieldValue,
    pub value: FieldValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseFailure {
    message: String,
    classification: Classification,
    causes: Vec<String>,
}

impl CaseFailure {
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
}

impl fmt::Display for CaseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Classified for CaseFailure {
    fn classification(&self) -> Classification {
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

#[derive(Clone, Debug)]
pub struct Case {
    pub operation_seed: u64,
    pub index: u64,
    pub seed: u64,
    pub mutation: Mutation,
    pub shrink_values: Vec<FieldValue>,
    pub recipe: Packet,
    pub built: Option<BuiltPacket>,
    pub decoded: Option<DecodedPacket>,
    pub outcome: CaseOutcome,
    pub error: Option<CaseFailure>,
    pub diagnostics: Vec<Diagnostic>,
}

/// What one offline campaign generated, built, retained, and took.
///
/// The module has no transmission seam, so a case is the only unit counted
/// here; the output boundary is what maps these onto the published
/// packet-operation columns.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub cases_generated: u64,
    pub cases_built: u64,
    pub bytes: u64,
    pub elapsed: Duration,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub seed: u64,
    pub first_case: u64,
    pub cases: Vec<Case>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

/// Final offline campaign metadata after every case event was published.
#[derive(Clone, Debug)]
pub struct Summary {
    pub seed: u64,
    pub first_case: u64,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}
