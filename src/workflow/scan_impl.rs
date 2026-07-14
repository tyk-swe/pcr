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
use crate::error::{Classification, Classified, Kind};
use crate::net::{
    DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES, ExchangeIo, NeighborResolver,
    RouteProvider,
};
use crate::packet::internal::{
    DEFAULT_MAX_TEMPLATE_PACKETS, DecodedPacket, Diagnostic, FieldValue, Packet, PacketTemplate,
    ProtocolRegistry, TemplateValues,
};
use crate::protocol::internal::{Icmpv4, Icmpv6, Ipv4, Ipv6, Tcp, Udp};

use super::clock::Clock;
use super::evidence::{
    EvidenceBudget, EvidenceBudgetError, ExchangeEvidence, ExchangeEvidenceError,
    MatchedResponseEvidence, preferred_latency, response_within_deadline,
    validate_exchange_evidence as validate_shared_exchange_evidence,
};
use super::nonzero_ipv4_identification;
use super::probe::Correlation;
use super::target::{AuthorizationError, Authorizer, Target};
use super::{AddressFamily, Stats, push_diagnostic_once};

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

#[path = "scan/adapter.rs"]
mod adapter;
#[path = "scan/classification.rs"]
mod classification;
#[path = "scan/engine.rs"]
mod engine;
#[path = "scan/error.rs"]
mod error;
#[path = "scan/model.rs"]
mod model;
#[cfg(test)]
#[path = "scan/tests.rs"]
mod tests;

pub use adapter::ClientExecutor;
pub use classification::{ScanResponseClassification, classify_scan_response};
pub use engine::{scan, scan_observed};
pub use error::{ScanError, ScanObservedError};
pub use model::{
    ScanBatch, ScanBatchExecution, ScanClassification, ScanEndpointResult, ScanExecutionError,
    ScanExecutor, ScanLimits, ScanMatchedResponse, ScanProbe, ScanProbeEvidence, ScanProbeStatus,
    ScanProgress, ScanProgressObserver, ScanRequest, ScanResult, ScanTransport,
};
