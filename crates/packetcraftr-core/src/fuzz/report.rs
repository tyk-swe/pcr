// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Classification, Classified};
use crate::{
    build::BuiltPacket, decode::DecodedPacket, diagnostic::Diagnostic, field::FieldValue,
    packet::Packet,
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

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
#[error("{message}")]
pub struct CaseFailure {
    message: String,
    classification: Classification,
    #[source]
    source: crate::error::Source,
}

impl CaseFailure {
    pub fn with_source(
        message: impl Into<String>,
        classification: Classification,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            classification,
            source: crate::error::Source::new(source),
        }
    }
}

impl Classified for CaseFailure {
    fn classification(&self) -> Classification {
        self.classification
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
    pub stats: Stats,
}

impl Report {
    #[must_use]
    pub fn from_summary(summary: Summary, cases: Vec<Case>) -> Self {
        Self {
            seed: summary.seed,
            first_case: summary.first_case,
            cases,
            stats: summary.stats,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Summary {
    pub seed: u64,
    pub first_case: u64,
    pub stats: Stats,
}
