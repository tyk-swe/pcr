// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

use super::layout::ByteRange;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// A machine-readable build, decode, session, or policy finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<ByteRange>,
}

impl Diagnostic {
    pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity: DiagnosticSeverity::Info,
            message: message.into(),
            layer: None,
            field: None,
            range: None,
        }
    }

    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity: DiagnosticSeverity::Warning,
            message: message.into(),
            layer: None,
            field: None,
            range: None,
        }
    }

    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity: DiagnosticSeverity::Error,
            message: message.into(),
            layer: None,
            field: None,
            range: None,
        }
    }

    pub fn at_layer(mut self, layer: usize) -> Self {
        self.layer = Some(layer);
        self
    }

    pub fn at_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }
}
