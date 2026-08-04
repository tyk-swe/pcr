// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded structured scanning over the shared resolver, policy, template,
//! exchange, matcher, and capture-evidence APIs.
//!
//! Scanning here means reachability and service-response inventory on networks
//! the operator is authorized to test: send a templated probe, correlate the
//! response, and classify it with capture-backed evidence. Every run requires
//! destination authorization and terminates on finite packet, byte, duration,
//! and evidence budgets.

use std::time::Duration;

use crate::kernel::evidence::EvidenceDiagnosticDescriptor;

pub const DEFAULT_SCAN_BATCH_SIZE: usize = 64;
pub const DEFAULT_MAX_SCAN_PORTS: usize = 1_024;
pub const DEFAULT_MAX_UNDECODED_SCAN_FRAMES: usize = 64;
pub const MAX_SCAN_ATTEMPTS: u32 = 32;
pub const MAX_SCAN_PROBES: usize = 100_000;
pub const MAX_SCAN_RATE: u32 = 1_000_000;
pub const MAX_SCAN_DURATION: Duration = packetcraftr_net::capture::MAX_TIMEOUT;

// Every generated scan probe is at most an Ethernet header plus IPv6 and TCP
// without options. Keeping this bound explicit lets the workflow authorize
// the complete multi-batch byte budget before the first route or send side
// effect, even though individual batches are delegated to Client::exchange.
const IPV4_PROBE_BYTES: u64 = 14 + 20 + 20;
const IPV6_PROBE_BYTES: u64 = 14 + 40 + 20;
const SCAN_EVIDENCE_DIAGNOSTICS: EvidenceDiagnosticDescriptor =
    EvidenceDiagnosticDescriptor::new("scan", "scan");

mod classification;
mod client_executor;
mod engine;
mod error;
mod model;
#[cfg(test)]
mod tests;

/// Executes scan batches through a client's capture-ready exchange lifecycle.
pub type ClientExecutor<'a, R, N, I> = crate::kernel::client_executor::ClientExecutor<
    'a,
    R,
    N,
    I,
    crate::kernel::client_executor::Scan,
>;
pub use crate::kernel::policy_authorizer::PolicyAuthorizer;
pub use classification::{
    ScanResponseClassification as ResponseClassification,
    classify_scan_response as classify_response,
};
pub use engine::scan as run;
pub use error::ScanError as Error;
pub use model::{
    ScanBatch as Batch, ScanBatchExecution as Execution, ScanClassification as Classification,
    ScanEndpointResult as Endpoint, ScanExecutor as Executor, ScanLimits as Limits,
    ScanMatchedResponse as MatchedResponse, ScanProbe as Probe, ScanProbeEvidence as ProbeEvidence,
    ScanProbeStatus as ProbeStatus, ScanRequest as Request, ScanResult as Result,
    ScanTransport as Transport,
};
