// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured diagnostics produced by build and decode operations.

mod model;

pub use model::{
    Diagnostic, DiagnosticCategory as Category, DiagnosticSeverity as Severity,
    has_integrity_failure, push_diagnostic_once,
};
