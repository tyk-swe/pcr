// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated traceroute to authorized destinations, with finite hop, attempt,
//! timeout, and evidence limits.

use std::time::Duration;

use crate::probe::evidence::EvidenceDiagnosticDescriptor;

pub const DEFAULT_FIRST_HOP: u8 = 1;
pub const DEFAULT_MAX_HOPS: u8 = 30;
pub const DEFAULT_PROBES_PER_HOP: u32 = 3;
pub const DEFAULT_UDP_PORT: u16 = 33_434;
pub const DEFAULT_TCP_PORT: u16 = 80;
pub const DEFAULT_MAX_UNDECODED_FRAMES: usize = 64;
pub const MAX_PROBES_PER_HOP: u32 = 32;
pub const MAX_PROBES: usize = 100_000;
pub const MAX_RATE: u32 = 1_000_000;
pub const MAX_DURATION: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;

// A generated probe is no larger than Ethernet + IPv6 + TCP without options.
// The deliberately conservative value makes complete byte-policy approval
// possible before any route, capture, neighbor, or send side effect.
const MAX_PROBE_BYTES: u64 = 14 + 40 + 20;
const SOURCE_PORT: u16 = crate::probe::EPHEMERAL_SOURCE_PORT_BASE;
const EVIDENCE_DIAGNOSTICS: EvidenceDiagnosticDescriptor =
    EvidenceDiagnosticDescriptor::new("traceroute", "traceroute");

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
pub use engine::{run, run_with_events};
pub use error::Error;
pub use model::{
    Batch, Completion, Event, Execution, Executor, Hop, Limits, Probe, ProbeEvidence, ProbeStatus,
    ProbeTarget, Report, Request, ResponseKind, Strategy, Summary, UndecodedEvidence,
};
