// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, structured traceroute over the shared authorization, exchange,
//! protocol-correlation, and capture-evidence contracts.

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::Serialize;
use thiserror::Error;

use crate::capture::Frame;
use crate::error::{Classification, Classified, Kind};
use crate::net::{
    DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES, ExchangeIo, NeighborResolver,
    RouteProvider,
};
use crate::packet::internal::{
    DecodedPacket, Diagnostic, FieldValue, Packet, PacketTemplate, ProtocolRegistry, TemplateValues,
};
use crate::protocol::internal::{Icmpv4, Icmpv6, Ipv4, Ipv6, Tcp, Udp};

use super::clock::Clock;
use super::evidence::{
    EvidenceBudget, EvidenceBudgetError, ExchangeEvidence, ExchangeEvidenceError,
    MatchedResponseEvidence, preferred_latency, response_within_deadline,
    validate_exchange_evidence as validate_shared_exchange_evidence,
};
use super::nonzero_ipv4_identification;
use super::probe::{self, Correlation, Transport as ProbeTransport};
use super::scan_impl::{MAX_SCAN_PROBES, MAX_SCAN_RATE};
use super::target::{AuthorizationError, Authorizer, Target};
use super::{AddressFamily, Stats, push_diagnostic_once};

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

#[path = "traceroute/adapter.rs"]
mod adapter;
#[path = "traceroute/classification.rs"]
mod classification;
#[path = "traceroute/engine.rs"]
mod engine;
#[path = "traceroute/error.rs"]
mod error;
#[path = "traceroute/model.rs"]
mod model;
#[cfg(test)]
#[path = "traceroute/tests.rs"]
mod tests;

pub use adapter::ClientExecutor;
pub use classification::{TracerouteResponseClassification, classify_traceroute_response};
pub use engine::traceroute;
pub use error::TracerouteError;
pub use model::{
    TracerouteBatch, TracerouteBatchExecution, TracerouteCompletion, TracerouteExecutionError,
    TracerouteExecutor, TracerouteHopResult, TracerouteLimits, TracerouteMatchedResponse,
    TracerouteProbe, TracerouteProbeEvidence, TracerouteProbeStatus, TracerouteRequest,
    TracerouteResponseKind, TracerouteResult, TracerouteStrategy, TracerouteUndecodedEvidence,
};
