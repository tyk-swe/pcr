//! Aggregate JSON and streaming NDJSON envelopes.

mod model;

pub use model::{
    AggregateErrorOutput as AggregateError, AggregateOutput as Aggregate, CaptureStats,
    DiagnosticOutput as Diagnostic, DiagnosticRangeOutput as DiagnosticRange,
    DiagnosticSeverityOutput as DiagnosticSeverity, OperationStats as Stats, OutputError as Error,
    OutputErrorKind as ErrorKind, StreamErrorRecord as StreamError, StreamRecord as Stream,
};
pub(crate) use model::{DiagnosticOutput, OperationStats, OutputError};
