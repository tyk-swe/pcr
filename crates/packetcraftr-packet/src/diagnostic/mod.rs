// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured diagnostics produced by build and decode operations.

mod model;

#[doc(hidden)]
pub use model::DiagnosticSeverity;
pub use model::{Diagnostic, DiagnosticSeverity as Severity, push_diagnostic_once};
