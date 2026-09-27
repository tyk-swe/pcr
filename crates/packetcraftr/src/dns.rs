// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DNS query construction, response validation, and retry execution.

use crate::execution::evidence::EvidenceDiagnosticDescriptor;

pub const HEADER_BYTES: usize = 12;
pub const DEFAULT_SERVER_PORT: u16 = 53;
pub const DEFAULT_ATTEMPTS: u32 = 1;
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
// Bit 6 is the sole reserved Z bit; AD (bit 5) and CD (bit 4) are DNSSEC flags.
const RESERVED_MASK: u16 = 0x0040;
const RCODE_MASK: u16 = 0x000f;
const CLASS_IN: u16 = 1;
const TYPE_OPT: u16 = 41;
const MAX_PROBE_OVERHEAD: u64 = 14 + 40 + 8;

pub mod batch;
mod engine;
mod error;
mod evidence;
mod executor;
mod plan;
mod report;
mod request;
mod reverse;
pub mod tcp;
#[cfg(test)]
mod tests;
pub mod wire;

pub use error::{Error, EvidenceFault};
pub use evidence::{ResponseClassification, classify_response, response_code_name};
pub use report::{
    Aggregate, AttemptEvidence, Collector, Completion, Event, EventContext, IncoherentReport,
    Outcome, RejectedRecord, Report, ResponseMetadata, Section, Transport, TransportEvidence,
    UndecodedEvidence, ValidatedResponse,
};
pub use request::{EdnsRequest, Limits, MessageLimits, QueryType, Request, TransportMode};

pub use plan::{Probe, unpredictable_source_port, unpredictable_transaction_id};
pub use reverse::reverse_name;

use packetcraftr_core::protocol::application::dns::{Edns, Name, Record, RecordValue};
