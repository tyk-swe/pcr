// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, structured traceroute over the shared authorization, exchange,
//! protocol-correlation, and capture-evidence contracts.

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capture::Frame;
use crate::error::{Classification, Classified, Kind};
use crate::net::{
    capture::{DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES},
    exchange::ExchangeIo,
    route::{NeighborResolver, RouteProvider},
};
use crate::packet::{
    Packet,
    decode::DecodedPacket,
    diagnostic::Diagnostic,
    registry::ProtocolRegistry,
    template::{PacketTemplate, TemplateValues},
};
use crate::protocol::{
    icmp::{Icmpv4, Icmpv6},
    network::{Ipv4, Ipv6},
    transport::{Tcp, Udp},
};

use super::clock::Clock;
use super::deadline::{Deadline, DeadlineExceeded};
use super::evidence::{
    EvidenceBudget, EvidenceDiagnosticDescriptor, ExchangeEvidence, ExchangeEvidenceError,
    MatchedResponseEvidence, ResponseEvidence, format_exchange_evidence_error, retain_evidence,
    validate_exchange_evidence as validate_shared_exchange_evidence,
};
use super::nonzero_ipv4_identification;
use super::probe::{self, Correlation, Transport as ProbeTransport};
use super::scan::{MAX_SCAN_PROBES, MAX_SCAN_RATE};
use super::target::{Authorizer, Target};
use super::{AddressFamily, BoundaryError, Stats, push_diagnostic_once};

pub const DEFAULT_TRACEROUTE_FIRST_HOP: u8 = 1;
pub const DEFAULT_TRACEROUTE_MAX_HOPS: u8 = 30;
pub const DEFAULT_TRACEROUTE_PROBES_PER_HOP: u32 = 3;
pub const DEFAULT_TRACEROUTE_UDP_PORT: u16 = 33_434;
pub const DEFAULT_TRACEROUTE_TCP_PORT: u16 = 80;
pub const DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES: usize = 64;
pub const MAX_TRACEROUTE_PROBES_PER_HOP: u32 = 32;
pub const MAX_TRACEROUTE_DURATION: Duration = crate::net::capture::MAX_TIMEOUT;

// A generated probe is no larger than Ethernet + IPv6 + TCP without options.
// The deliberately conservative value makes complete byte-policy approval
// possible before any route, capture, neighbor, or send side effect.
const MAX_TRACEROUTE_PROBE_BYTES: u64 = 14 + 40 + 20;
const TRACEROUTE_SOURCE_PORT: u16 = 49_152;
const TRACEROUTE_EVIDENCE_DIAGNOSTICS: EvidenceDiagnosticDescriptor =
    EvidenceDiagnosticDescriptor::new("traceroute", "traceroute");

mod adapter;
mod classification;
mod engine;
mod error;
mod model;
#[cfg(test)]
mod tests;

pub use super::target_adapter::PolicyAuthorizer;
pub use adapter::ClientExecutor;
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

use classification::classify_traceroute_response;
#[cfg(test)]
use engine::traceroute;
use error::TracerouteError;
use model::{
    TracerouteBatch, TracerouteBatchExecution, TracerouteCompletion, TracerouteExecutor,
    TracerouteHopResult, TracerouteLimits, TracerouteMatchedResponse, TracerouteProbe,
    TracerouteProbeEvidence, TracerouteProbeStatus, TracerouteRequest, TracerouteResponseKind,
    TracerouteResult, TracerouteStrategy, TracerouteUndecodedEvidence,
};
