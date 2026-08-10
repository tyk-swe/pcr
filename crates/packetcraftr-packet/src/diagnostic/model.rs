// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

use super::super::layout::ByteRange;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// Stable semantic category independent of a diagnostic's display code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCategory {
    /// A general build, decode, session, or policy finding.
    General,
    /// A finding about failed packet-integrity validation.
    Integrity,
}

/// A machine-readable build, decode, session, or policy finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub category: DiagnosticCategory,
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
            category: DiagnosticCategory::General,
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
            category: DiagnosticCategory::General,
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
            category: DiagnosticCategory::General,
            severity: DiagnosticSeverity::Error,
            message: message.into(),
            layer: None,
            field: None,
            range: None,
        }
    }

    /// Creates a warning for a failed packet-integrity check.
    pub fn integrity_warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            category: DiagnosticCategory::Integrity,
            severity: DiagnosticSeverity::Warning,
            message: message.into(),
            layer: None,
            field: None,
            range: None,
        }
    }

    #[must_use]
    pub fn at_layer(mut self, layer: usize) -> Self {
        self.layer = Some(layer);
        self
    }

    #[must_use]
    pub fn at_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }
}

/// Returns whether diagnostics contain a non-informational integrity failure.
///
/// Codes and messages are deliberately excluded from this decision so display
/// wording can change without changing packet-correlation behavior.
pub fn has_integrity_failure(diagnostics: &[Diagnostic]) -> bool {
    diagnostics.iter().any(|diagnostic| {
        diagnostic.category == DiagnosticCategory::Integrity
            && diagnostic.severity != DiagnosticSeverity::Info
    })
}

/// Appends `diagnostic` unless one with the same code is already present.
pub fn push_diagnostic_once(diagnostics: &mut Vec<Diagnostic>, diagnostic: Diagnostic) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_behavior_depends_on_category_not_code_or_message() {
        assert!(has_integrity_failure(&[Diagnostic::integrity_warning(
            "decode.validation_failed",
            "renamed integrity diagnostic",
        )]));
        assert!(!has_integrity_failure(&[Diagnostic::warning(
            "decode.checksum_sounding_code",
            "message mentions checksum corruption",
        )]));
        let mut informational = Diagnostic::info("decode.note", "checksum was not verified");
        informational.category = DiagnosticCategory::Integrity;
        assert!(!has_integrity_failure(&[informational]));
    }
}
