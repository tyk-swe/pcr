// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod execution;
mod request;
mod result;

pub use execution::{ScanBatch, ScanBatchExecution, ScanExecutor, ScanProbe};
pub use request::{ScanLimits, ScanRequest, ScanTransport};
pub use result::{
    ScanClassification, ScanEndpointResult, ScanProbeEvidence, ScanProbeStatus, ScanResult,
};
