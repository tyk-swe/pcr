// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated scanning of authorized targets with finite packet, byte,
//! duration, and evidence budgets.

use std::time::Duration;

use crate::probe::evidence::EvidenceDiagnosticDescriptor;

pub const DEFAULT_SCAN_BATCH_SIZE: usize = 64;
pub const DEFAULT_MAX_SCAN_PORTS: usize = 1_024;
pub const DEFAULT_MAX_UNDECODED_SCAN_FRAMES: usize = 64;
pub const MAX_SCAN_ATTEMPTS: u32 = 32;
pub const MAX_SCAN_PROBES: usize = 100_000;
pub const MAX_SCAN_RATE: u32 = 1_000_000;
pub const MAX_SCAN_DURATION: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;

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
mod evidence;
mod model;
mod plan;
mod probe;
#[cfg(test)]
mod tests;

pub use classification::{ResponseClassification, classify_response};
pub use engine::run;
pub use error::Error;
pub use model::{
    Batch, Classification, Endpoint, Execution, Executor, Limits, Probe, ProbeEvidence,
    ProbeStatus, Request, Result, Transport,
};
