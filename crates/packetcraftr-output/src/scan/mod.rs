// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured scan output.

mod model;
pub use model::{
    ProbeEvidenceOutput as Evidence, ScanClassification as Classification,
    ScanCommandResult as Result, ScanPortOutput as Port, ScanProbeStatus as ProbeStatus,
    ScanStreamCommandResult as Event,
};
