// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured diagnostics produced by build and decode operations.

mod model;

pub use model::DiagnosticSeverity;
pub use model::{Diagnostic, DiagnosticSeverity as Severity};

/// Appends `diagnostic` unless a diagnostic with the same code is already
/// present. Repeating one condition per operation would inflate evidence
/// without adding information.
pub fn push_diagnostic_once(diagnostics: &mut Vec<Diagnostic>, diagnostic: Diagnostic) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}
