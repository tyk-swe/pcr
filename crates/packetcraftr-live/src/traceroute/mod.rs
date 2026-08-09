// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated traceroute to authorized destinations, with finite hop, attempt,
//! timeout, and evidence limits.

use std::time::Duration;

use crate::probe::evidence::EvidenceDiagnosticDescriptor;

pub const DEFAULT_TRACEROUTE_FIRST_HOP: u8 = 1;
pub const DEFAULT_TRACEROUTE_MAX_HOPS: u8 = 30;
pub const DEFAULT_TRACEROUTE_PROBES_PER_HOP: u32 = 3;
pub const DEFAULT_TRACEROUTE_UDP_PORT: u16 = 33_434;
pub const DEFAULT_TRACEROUTE_TCP_PORT: u16 = 80;
pub const DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES: usize = 64;
pub const MAX_TRACEROUTE_PROBES_PER_HOP: u32 = 32;
pub const MAX_TRACEROUTE_DURATION: Duration = packetcraftr_network::capture::MAX_TIMEOUT;

// A generated probe is no larger than Ethernet + IPv6 + TCP without options.
// The deliberately conservative value makes complete byte-policy approval
// possible before any route, capture, neighbor, or send side effect.
const MAX_TRACEROUTE_PROBE_BYTES: u64 = 14 + 40 + 20;
const TRACEROUTE_SOURCE_PORT: u16 = 49_152;
const TRACEROUTE_EVIDENCE_DIAGNOSTICS: EvidenceDiagnosticDescriptor =
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

pub use crate::target::PolicyAuthorizer;
pub use classification::{
    TracerouteResponseClassification as ResponseClassification,
    classify_traceroute_response as classify_response,
};
pub use engine::traceroute as run;
pub use error::TracerouteError as Error;
pub use model::{
    TracerouteBatch as Batch, TracerouteBatchExecution as Execution,
    TracerouteCompletion as Completion, TracerouteExecutor as Executor, TracerouteHopResult as Hop,
    TracerouteLimits as Limits, TracerouteMatchedResponse as MatchedResponse,
    TracerouteProbe as Probe, TracerouteProbeEvidence as ProbeEvidence,
    TracerouteProbeStatus as ProbeStatus, TracerouteRequest as Request,
    TracerouteResponseKind as ResponseKind, TracerouteResult as Result,
    TracerouteStrategy as Strategy, TracerouteUndecodedEvidence as UndecodedEvidence,
};
