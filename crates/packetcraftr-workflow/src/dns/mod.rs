// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DNS query construction, response validation, relevance filtering,
//! and retry execution over the shared target-policy and exchange seams.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::Serialize;
use thiserror::Error;

use packetcraftr_capture::Frame;
use packetcraftr_error::{Classification, Classified, Kind};
use packetcraftr_net::{
    capture::{DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES},
    route::{NeighborResolver, RouteProvider},
};
use packetcraftr_packet::{
    Packet,
    codec::NetworkEnvelope,
    decode::DecodedPacket,
    diagnostic::{Diagnostic, DiagnosticSeverity, push_diagnostic_once},
    layer::{MalformedLayer, Raw},
    registry::ProtocolRegistry,
    template::PacketTemplate,
};
use packetcraftr_protocol::{
    application::Dns,
    network::{Ipv4, Ipv6},
    transport::Udp,
};

use super::clock::Clock;
use super::evidence::{
    EvidenceBudget, EvidenceDiagnosticDescriptor, ExchangeEvidenceError, ResponseCandidate,
    ResponseEvidence, push_undecoded_limit_diagnostic, response_within_deadline, retain_evidence,
    select_response_candidate, validate_aggregate_evidence_limits,
    validate_capture_statistics_evidence, validate_response_frames_and_deadlines,
    validate_sent_byte_accounting,
};
use super::nonzero_ipv4_identification;
use super::probe::{self, Transport as ProbeTransport};
use super::scan::MAX_SCAN_RATE;
use super::target::{Authorizer, Target};
use super::{AddressFamily, BoundaryError, Stats};
use packetcraftr_budget::{Deadline, DeadlineExceeded};

pub const DNS_HEADER_BYTES: usize = 12;
pub const DEFAULT_DNS_SERVER_PORT: u16 = 53;
pub const DNS_EPHEMERAL_SOURCE_PORT_BASE: u16 = 49_152;
pub const DEFAULT_DNS_ATTEMPTS: u32 = 1;
pub const DEFAULT_MAX_DNS_RECORDS: usize = 512;
pub const DEFAULT_MAX_DNS_NAME_POINTERS: usize = 32;
pub const DEFAULT_MAX_DNS_TXT_STRINGS: usize = 256;
pub const DEFAULT_MAX_DNS_TXT_BYTES: usize = 16_384;
pub const DEFAULT_MAX_REJECTED_DNS_RECORDS: usize = 128;
pub const DEFAULT_MAX_UNDECODED_DNS_FRAMES: usize = 32;
pub const MAX_DNS_ATTEMPTS: u32 = 32;
pub const MAX_DNS_MESSAGE_BYTES: usize = u16::MAX as usize;
pub const MAX_DNS_RECORDS: usize = 4_096;
pub const MAX_DNS_NAME_POINTERS: usize = 128;
pub const MAX_DNS_DURATION: Duration = packetcraftr_net::capture::MAX_TIMEOUT;

const DNS_EVIDENCE_DIAGNOSTICS: EvidenceDiagnosticDescriptor =
    EvidenceDiagnosticDescriptor::new("dns", "DNS");

const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_AUTHORITATIVE: u16 = 0x0400;
const DNS_FLAG_TRUNCATED: u16 = 0x0200;
const DNS_FLAG_RECURSION_DESIRED: u16 = 0x0100;
const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const DNS_FLAG_AUTHENTICATED_DATA: u16 = 0x0020;
const DNS_FLAG_CHECKING_DISABLED: u16 = 0x0010;
const DNS_OPCODE_MASK: u16 = 0x7800;
// Bit 6 is the sole reserved Z bit. AD (bit 5) and CD (bit 4) are defined by
// DNSSEC and therefore must not be rejected as reserved header data.
const DNS_RESERVED_MASK: u16 = 0x0040;
const DNS_RCODE_MASK: u16 = 0x000f;
const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_OPT: u16 = 41;
const MAX_DNS_PROBE_OVERHEAD: u64 = 14 + 40 + 8;

mod client_executor;
mod engine;
mod error;
mod model;
#[cfg(test)]
mod tests;
mod wire;

/// Executes DNS queries through a client's capture-ready exchange lifecycle.
pub type ClientExecutor<'a, R, N, I> =
    super::client_executor::ClientExecutor<'a, R, N, I, super::client_executor::Dns>;
pub use super::policy_authorizer::PolicyAuthorizer;
pub use engine::dns as run;
pub use error::{DnsError as Error, DnsWireError as WireError};
pub use model::{
    DnsAttemptEvidence as AttemptEvidence, DnsAttemptStatus as AttemptStatus, DnsEdns as Edns,
    DnsEdnsOption as EdnsOption, DnsExchange as Exchange, DnsExchangeExecution as Execution,
    DnsExecutor as Executor, DnsLimits as Limits, DnsMatchedResponse as MatchedResponse,
    DnsName as Name, DnsOutcome as Outcome, DnsProbe as Probe, DnsQueryType as QueryType,
    DnsRecord as Record, DnsRecordValue as RecordValue, DnsRejectedRecord as RejectedRecord,
    DnsRequest as Request, DnsResult as Result, DnsSection as Section,
    DnsUndecodedEvidence as UndecodedEvidence, ValidatedDnsResponse as ValidatedResponse,
};
pub use wire::{
    DnsResponseClassification as ResponseClassification, canonical_query_name,
    classify_dns_response as classify_response, decode_dns_response as decode_response,
    decode_dns_tcp_frame as decode_tcp_frame, encode_dns_query as encode_query, response_code_name,
};

#[cfg(test)]
use engine::dns;
use error::{DnsError, DnsWireError};
use model::{
    DnsAttemptEvidence, DnsAttemptStatus, DnsEdns, DnsEdnsOption, DnsExchange,
    DnsExchangeExecution, DnsExecutor, DnsLimits, DnsMatchedResponse, DnsName, DnsOutcome,
    DnsProbe, DnsQueryType, DnsRecord, DnsRecordValue, DnsRejectedRecord, DnsRequest, DnsResult,
    DnsSection, DnsUndecodedEvidence, ValidatedDnsResponse,
};
use wire::{DnsResponseClassification, classify_dns_response, encode_dns_query};
#[cfg(test)]
use wire::{decode_dns_response, decode_dns_tcp_frame};
