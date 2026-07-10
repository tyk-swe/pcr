// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Portable workflow boundary for replay, scan, traceroute, DNS, and fuzz tooling.
//!
//! Tool implementations are added incrementally behind this module so the
//! eventual `packetcraftr-tools` extraction does not change root imports.

mod replay;
mod scan;
mod traceroute;

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
pub use traceroute::{
    classify_traceroute_response, traceroute, AuthorizedTracerouteTarget, TracerouteAddressFamily,
    TracerouteAuthorizationError, TracerouteBatch, TracerouteBatchExecution, TracerouteCompletion,
    TracerouteError, TracerouteExecutionError, TracerouteExecutor, TracerouteHopResult,
    TracerouteLimits, TracerouteMatchedResponse, TracerouteProbe, TracerouteProbeEvidence,
    TracerouteProbeStatus, TracerouteRequest, TracerouteResponseClassification,
    TracerouteResponseKind, TracerouteResult, TracerouteStats, TracerouteStrategy,
    TracerouteTarget, TracerouteUndecodedEvidence, DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES,
    DEFAULT_TRACEROUTE_FIRST_HOP, DEFAULT_TRACEROUTE_MAX_HOPS, DEFAULT_TRACEROUTE_PROBES_PER_HOP,
    DEFAULT_TRACEROUTE_TCP_PORT, DEFAULT_TRACEROUTE_UDP_PORT, MAX_TRACEROUTE_DURATION,
    MAX_TRACEROUTE_PROBES_PER_HOP,
};

pub use scan::SystemScanClock as SystemTracerouteClock;
pub use scan::{ScanAuthorizer as TracerouteAuthorizer, ScanClock as TracerouteClock};
