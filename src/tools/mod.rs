// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Portable workflow boundary for replay, scan, traceroute, DNS, and fuzz tooling.
//!
//! Tool implementations are added incrementally behind this module so the
//! eventual `packetcraftr-tools` extraction does not change root imports.

mod replay;
mod scan;

pub use replay::{
    replay_capture, ReplayAuthorizationError, ReplayAuthorizer, ReplayClock, ReplayError,
    ReplayFrameEvidence, ReplayLimits, ReplayOptions, ReplaySummary, ReplayTransmission,
    ReplayTransmitter, SystemReplayClock, MAX_REPLAY_DURATION,
};
pub use scan::{
    classify_scan_response, scan, AuthorizedScanTarget, ScanAddressFamily, ScanAuthorizationError,
    ScanAuthorizer, ScanBatch, ScanBatchExecution, ScanClassification, ScanClock,
    ScanEndpointResult, ScanError, ScanExecutionError, ScanExecutor, ScanLimits,
    ScanMatchedResponse, ScanProbe, ScanProbeEvidence, ScanProbeStatus, ScanRequest,
    ScanResponseClassification, ScanResult, ScanStats, ScanTarget, ScanTransport, SystemScanClock,
    DEFAULT_MAX_SCAN_PORTS, DEFAULT_MAX_UNDECODED_SCAN_FRAMES, DEFAULT_SCAN_BATCH_SIZE,
    MAX_SCAN_ATTEMPTS, MAX_SCAN_DURATION, MAX_SCAN_PROBES, MAX_SCAN_RATE,
};
