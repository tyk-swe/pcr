// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded structured scanning over the shared resolver, policy, template,
//! exchange, matcher, and capture-evidence APIs.

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::Serialize;
use thiserror::Error;

use crate::capture::Frame;
use crate::error::{Classified, Kind};
use crate::net::{
    capture::{DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES},
    exchange::ExchangeIo,
    route::{NeighborResolver, RouteProvider},
};
use crate::packet::{
    Packet,
    decode::DecodedPacket,
    diagnostic::Diagnostic,
    field::FieldValue,
    registry::ProtocolRegistry,
    template::{DEFAULT_MAX_TEMPLATE_PACKETS, PacketTemplate, TemplateValues},
};
use crate::protocol::{
    icmp::{Icmpv4, Icmpv6},
    network::{Ipv4, Ipv6},
    transport::{Tcp, Udp},
};

use super::clock::Clock;
use super::evidence::{
    EvidenceBudget, EvidenceBudgetError, ExchangeEvidence, ExchangeEvidenceError,
    MatchedResponseEvidence, preferred_latency, response_within_deadline,
    validate_exchange_evidence as validate_shared_exchange_evidence,
};
use super::nonzero_ipv4_identification;
use super::probe::Correlation;
use super::target::{Authorizer, Target};
use super::{AddressFamily, BoundaryError, Stats, push_diagnostic_once};

pub const DEFAULT_SCAN_BATCH_SIZE: usize = 64;
pub const DEFAULT_MAX_SCAN_PORTS: usize = 1_024;
pub const DEFAULT_MAX_UNDECODED_SCAN_FRAMES: usize = 64;
pub const MAX_SCAN_ATTEMPTS: u32 = 32;
pub const MAX_SCAN_PROBES: usize = 100_000;
pub const MAX_SCAN_RATE: u32 = 1_000_000;
pub const MAX_SCAN_DURATION: Duration = crate::net::capture::MAX_TIMEOUT;

// Every generated scan probe is at most an Ethernet header plus IPv6 and TCP
// without options. Keeping this bound explicit lets the workflow authorize
// the complete multi-batch byte budget before the first route or send side
// effect, even though individual batches are delegated to Client::exchange.
const IPV4_PROBE_BYTES: u64 = 14 + 20 + 20;
const IPV6_PROBE_BYTES: u64 = 14 + 40 + 20;

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

use classification::{ScanResponseClassification, classify_scan_response};
#[cfg(test)]
use engine::scan;
use error::ScanError;
use model::{
    ScanBatch, ScanBatchExecution, ScanClassification, ScanEndpointResult, ScanExecutor,
    ScanLimits, ScanMatchedResponse, ScanProbe, ScanProbeEvidence, ScanProbeStatus, ScanRequest,
    ScanResult, ScanTransport,
};
