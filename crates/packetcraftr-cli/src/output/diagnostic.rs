// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The published diagnostic record and its severity vocabulary.

use serde::Serialize;

use packetcraftr_core::diagnostic as library;

published_enum! {
    /// Diagnostic weight, ordered from least to most severe.
    pub enum Severity from library::Severity {
        Info => "info",
        Warning => "warning",
        Error => "error",
    }
}

/// A machine-readable build, decode, session, or policy finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
}

impl From<library::Diagnostic> for Diagnostic {
    fn from(value: library::Diagnostic) -> Self {
        Self {
            code: value.code,
            severity: value.severity.into(),
            message: value.message,
            layer: value.layer,
            field: value.field,
        }
    }
}

impl From<&library::Diagnostic> for Diagnostic {
    fn from(value: &library::Diagnostic) -> Self {
        value.clone().into()
    }
}
