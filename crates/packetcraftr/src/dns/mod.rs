// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DNS query construction, response validation, relevance filtering,
//! and retry execution over the shared target-policy and exchange seams.
//!
//! Each attempt begins over UDP. When [`Request::tcp_fallback`] is true, one
//! matching validated response with the truncation flag may continue over
//! DNS-over-TCP to the same reauthorized numeric endpoint. Both phases share
//! the attempt timeout. TCP framing and allocation are bounded, accepted
//! responses receive the same transaction/question validation as UDP, and TCP
//! socket bytes are never represented as captured [`Frame`](packetcraftr_core::frame::Frame)
//! evidence.

use std::time::Duration;

use crate::probe::evidence::EvidenceDiagnosticDescriptor;

pub const HEADER_BYTES: usize = 12;
pub const DEFAULT_SERVER_PORT: u16 = 53;
pub const DEFAULT_ATTEMPTS: u32 = 1;
/// DNS queries retry one validated truncated UDP response over TCP by default.
pub const DEFAULT_TCP_FALLBACK: bool = true;
pub const DEFAULT_MAX_RECORDS: usize = 512;
pub const DEFAULT_MAX_NAME_POINTERS: usize = 32;
pub const DEFAULT_MAX_TXT_STRINGS: usize = 256;
pub const DEFAULT_MAX_TXT_BYTES: usize = 16_384;
pub const DEFAULT_MAX_REJECTED_RECORDS: usize = 128;
pub const DEFAULT_MAX_UNDECODED_FRAMES: usize = 32;
pub const MAX_ATTEMPTS: u32 = 32;
pub const MAX_MESSAGE_BYTES: usize = u16::MAX as usize;
pub const MAX_RECORDS: usize = 4_096;
pub const MAX_NAME_POINTERS: usize = 128;
pub const MAX_RATE: u32 = 1_000_000;
pub const MAX_DURATION: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;

const EVIDENCE_DIAGNOSTICS: EvidenceDiagnosticDescriptor =
    EvidenceDiagnosticDescriptor::new("dns.evidence_limit", "dns.undecoded_limit", "DNS");

const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_AUTHORITATIVE: u16 = 0x0400;
const FLAG_TRUNCATED: u16 = 0x0200;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const FLAG_AUTHENTICATED_DATA: u16 = 0x0020;
const FLAG_CHECKING_DISABLED: u16 = 0x0010;
const OPCODE_MASK: u16 = 0x7800;
// Bit 6 is the sole reserved Z bit. AD (bit 5) and CD (bit 4) are defined by
// DNSSEC and therefore must not be rejected as reserved header data.
const RESERVED_MASK: u16 = 0x0040;
const RCODE_MASK: u16 = 0x000f;
const CLASS_IN: u16 = 1;
const TYPE_OPT: u16 = 41;
const MAX_PROBE_OVERHEAD: u64 = 14 + 40 + 8;

mod classification;
mod client_executor;
mod engine;
mod error;
mod evidence;
mod model;
mod plan;
mod probe;
pub mod tcp;
#[cfg(test)]
mod tests;
mod wire;

pub use classification::{ResponseClassification, classify_response, response_code_name};
pub use engine::{run, run_with_events};
pub use error::{Error, WireError};
pub use model::{
    AttemptEvidence, Edns, EdnsOption, Event, EventContext, Exchange, Execution, Executor, Limits,
    MessageLimits, Name, Outcome, Probe, QueryType, Record, RecordValue, RejectedRecord, Report,
    Request, ResponseMetadata, Section, Summary, TcpExchange, TcpExecution, Transport,
    UndecodedEvidence, ValidatedResponse,
};
pub use probe::{unpredictable_source_port, unpredictable_transaction_id};
pub use wire::{canonical_query_name, decode_response, decode_tcp_frame, encode_query};
