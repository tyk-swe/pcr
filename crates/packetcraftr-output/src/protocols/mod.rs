// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Built-in protocol discovery output.

mod model;

pub use model::{
    ProtocolDetail as Detail, ProtocolDetailResult as DetailResult, ProtocolField as Field,
    ProtocolFieldKind as FieldKind, ProtocolListResult as ListResult, ProtocolSummary as Summary,
};
