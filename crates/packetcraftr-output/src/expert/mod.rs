// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured expert-analysis output.

mod model;
pub use model::{
    ExpertCodeCount as CodeCount, ExpertCommandResult as Result, ExpertFindingOutput as Finding,
    ExpertSeverity as Severity, ExpertStreamTransport as StreamTransport,
};
