//! Structured diagnostics produced by build and decode operations.

mod model;

pub(crate) use model::DiagnosticSeverity;
pub use model::{Diagnostic, DiagnosticSeverity as Severity};
