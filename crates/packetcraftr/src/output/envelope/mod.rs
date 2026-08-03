// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate JSON and streaming NDJSON envelopes.

mod model;

pub use packetcraftr_core::error::Kind as ErrorKind;

pub use model::{
    AggregateErrorOutput as AggregateError, AggregateOutput as Aggregate, CaptureStats,
    DiagnosticOutput as Diagnostic, DiagnosticRangeOutput as DiagnosticRange,
    DiagnosticSeverityOutput as DiagnosticSeverity, OperationStats as Stats, OutputError as Error,
    StreamErrorRecord as StreamError, StreamRecord as Stream,
};
pub(crate) use model::{DiagnosticOutput, OperationStats, OutputError};
