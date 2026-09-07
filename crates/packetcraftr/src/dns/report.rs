// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::protocol::application::dns::name::{MAX_LABEL_LEN, MAX_NAME_LEN};

use crate::Stats;

use super::request::QueryType;
use crate::dns::TYPE_OPT;
use crate::dns::classification::response_code_name;
use crate::dns::error::WireError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

/// A lossless DNS wire name. Labels retain their exact octets; DNS semantic
/// equality folds ASCII letters only, and presentation escaping is deferred
/// to [`fmt::Display`].
#[derive(Clone, Debug, Eq)]
pub struct Name {
    pub(in crate::dns) labels: Vec<Bytes>,
}

impl Name {
    pub(in crate::dns) fn root() -> Self {
        Self { labels: Vec::new() }
    }

    pub(in crate::dns) fn from_canonical_ascii(value: &str) -> Self {
        if value == "." {
            return Self::root();
        }
        Self {
            labels: value
                .trim_end_matches('.')
                .split('.')
                .map(|label| Bytes::copy_from_slice(label.as_bytes()))
                .collect(),
        }
    }

    pub fn from_labels<I, B>(labels: I) -> Result<Self, WireError>
    where
        I: IntoIterator<Item = B>,
        B: Into<Bytes>,
    {
        let labels = labels.into_iter().map(Into::into).collect::<Vec<_>>();
        let mut wire_length = 1usize;
        for label in &labels {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(WireError::InvalidName {
                    message: format!("wire labels must contain 1..={MAX_LABEL_LEN} octets"),
                });
            }
            wire_length = wire_length
                .checked_add(label.len())
                .and_then(|length| length.checked_add(1))
                .ok_or(WireError::NameTooLong)?;
        }
        if wire_length > MAX_NAME_LEN {
            return Err(WireError::NameTooLong);
        }
        Ok(Self { labels })
    }

    pub fn labels(&self) -> &[Bytes] {
        &self.labels
    }

    pub(in crate::dns) fn is_root(&self) -> bool {
        self.labels.is_empty()
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.labels.len() == other.labels.len()
            && self
                .labels
                .iter()
                .zip(&other.labels)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return formatter.write_str(".");
        }
        for (label_index, label) in self.labels.iter().enumerate() {
            if label_index != 0 {
                formatter.write_str(".")?;
            }
            for byte in label {
                if byte.is_ascii_graphic() && !matches!(*byte, b'.' | b'\\') {
                    formatter.write_char(char::from(*byte))?;
                } else {
                    write!(formatter, "\\{byte:03}")?;
                }
            }
        }
        formatter.write_str(".")
    }
}

impl Serialize for Name {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Edns {
    pub udp_payload_size: u16,
    pub extended_response_code: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    pub flags: u16,
    pub options: Vec<EdnsOption>,
}

impl fmt::Display for Section {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Answer => "answer",
            Self::Authority => "authority",
            Self::Additional => "additional",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordValue {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Caa {
        flags: u8,
        tag: Bytes,
        value: Bytes,
    },
    Cname(Name),
    Mx {
        preference: u16,
        exchange: Name,
    },
    Ns(Name),
    Ptr(Name),
    Soa {
        primary_name_server: Name,
        responsible_mailbox: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    Txt(Vec<Bytes>),
    Opt(Edns),
    Unknown {
        type_code: u16,
        rdata: Bytes,
    },
}

impl RecordValue {
    pub const fn type_code(&self) -> u16 {
        match self {
            Self::A(_) => 1,
            Self::Ns(_) => 2,
            Self::Cname(_) => 5,
            Self::Soa { .. } => 6,
            Self::Ptr(_) => 12,
            Self::Mx { .. } => 15,
            Self::Txt(_) => 16,
            Self::Aaaa(_) => 28,
            Self::Srv { .. } => 33,
            Self::Caa { .. } => 257,
            Self::Opt(_) => TYPE_OPT,
            Self::Unknown { type_code, .. } => *type_code,
        }
    }

    pub(in crate::dns) fn referenced_name(&self) -> Option<&Name> {
        match self {
            Self::Cname(value) | Self::Ns(value) => Some(value),
            Self::Mx { exchange, .. } => Some(exchange),
            Self::Srv { target, .. } => Some(target),
            Self::A(_)
            | Self::Aaaa(_)
            | Self::Caa { .. }
            | Self::Ptr(_)
            | Self::Soa { .. }
            | Self::Txt(_)
            | Self::Opt(_)
            | Self::Unknown { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub owner: Name,
    pub class: u16,
    pub ttl: u32,
    pub value: RecordValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RejectedRecord {
    pub section: Section,
    pub index: usize,
    pub owner: String,
    pub type_code: u16,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseMetadata {
    pub response_code: u16,
    pub edns: Option<Edns>,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub rejected_record_count: usize,
}

impl ResponseMetadata {
    pub fn response_code_name(&self) -> &'static str {
        response_code_name(self.response_code)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedResponse {
    pub metadata: ResponseMetadata,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub rejected_records: Vec<RejectedRecord>,
}

impl ValidatedResponse {
    pub fn response_code_name(&self) -> &'static str {
        self.metadata.response_code_name()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Response,
    Truncated,
    Timeout,
    Unrelated,
    DecodeFailure,
    NetworkFailure,
}

/// Transport used by one DNS attempt phase or accepted response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    /// The stable text and structured-output name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Outcome {
    /// Precedence across retries and across several correlated frames in one
    /// attempt: the most informative outcome seen is the one reported.
    ///
    /// A timeout ranks last precisely because it carries no evidence, so any
    /// later attempt that learns something replaces it.
    pub(in crate::dns) const fn retry_rank(self) -> u8 {
        match self {
            Self::Response => 5,
            Self::Truncated => 4,
            Self::NetworkFailure => 3,
            Self::DecodeFailure => 2,
            Self::Unrelated => 1,
            Self::Timeout => 0,
        }
    }

    /// The name the CLI prints, identical to the serialized one.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Response => "response",
            Self::Truncated => "truncated",
            Self::Timeout => "timeout",
            Self::Unrelated => "unrelated",
            Self::DecodeFailure => "decode_failure",
            Self::NetworkFailure => "network_failure",
        }
    }
}

/// Transport-specific evidence. Kernel TCP never carries a captured frame;
/// a transmitted UDP query always has a source port and transmission time.
#[derive(Clone, Debug)]
pub enum AttemptTransport {
    Udp {
        source_port: u16,
        sent_at: SystemTime,
        response: Option<Frame>,
    },
    Tcp {
        source_port: Option<u16>,
        sent_at: Option<SystemTime>,
    },
}

#[derive(Clone, Debug)]
pub struct AttemptEvidence {
    pub attempt: u32,
    pub exchange: AttemptTransport,
    pub server_address: IpAddr,
    pub status: Outcome,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response_code: Option<u16>,
    pub reason: String,
}

impl AttemptEvidence {
    pub const fn transport(&self) -> Transport {
        match self.exchange {
            AttemptTransport::Udp { .. } => Transport::Udp,
            AttemptTransport::Tcp { .. } => Transport::Tcp,
        }
    }
    pub const fn source_port(&self) -> Option<u16> {
        match self.exchange {
            AttemptTransport::Udp { source_port, .. } => Some(source_port),
            AttemptTransport::Tcp { source_port, .. } => source_port,
        }
    }
    pub const fn sent_at(&self) -> Option<SystemTime> {
        match self.exchange {
            AttemptTransport::Udp { sent_at, .. } => Some(sent_at),
            AttemptTransport::Tcp { sent_at, .. } => sent_at,
        }
    }
    pub fn response(&self) -> Option<&Frame> {
        match &self.exchange {
            AttemptTransport::Udp { response, .. } => response.as_ref(),
            AttemptTransport::Tcp { .. } => None,
        }
    }
}

/// Incoherent independently supplied DNS result parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("incoherent DNS evidence: {0}")]
pub struct EvidenceError(pub(in crate::dns) &'static str);

/// The terminal DNS decision and its accepted response metadata. Private
/// fields prevent a successful outcome without an accepted transport/header.
#[derive(Clone, Debug)]
pub struct Completion {
    pub(in crate::dns) outcome: Outcome,
    pub(in crate::dns) fallback_attempted: bool,
    pub(in crate::dns) accepted_transport: Option<Transport>,
    pub(in crate::dns) response: Option<ResponseMetadata>,
}

impl Completion {
    pub fn new(
        outcome: Outcome,
        fallback_attempted: bool,
        accepted_transport: Option<Transport>,
        response: Option<ResponseMetadata>,
    ) -> Result<Self, EvidenceError> {
        let completion = Self {
            outcome,
            fallback_attempted,
            accepted_transport,
            response,
        };
        completion.validate()?;
        Ok(completion)
    }
    pub(in crate::dns) fn validate(&self) -> Result<(), EvidenceError> {
        let accepts = matches!(self.outcome, Outcome::Response | Outcome::Truncated);
        if accepts != self.accepted_transport.is_some() || accepts != self.response.is_some() {
            return Err(EvidenceError(
                "an accepted outcome requires a transport and response header",
            ));
        }
        if let Some(response) = &self.response
            && response.truncated != (self.outcome == Outcome::Truncated)
        {
            return Err(EvidenceError(
                "response truncation must agree with the outcome",
            ));
        }
        if self.accepted_transport == Some(Transport::Tcp)
            && (!self.fallback_attempted || self.outcome != Outcome::Response)
        {
            return Err(EvidenceError(
                "accepted TCP requires an attempted fallback and a complete response",
            ));
        }
        Ok(())
    }
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }
    pub const fn fallback_attempted(&self) -> bool {
        self.fallback_attempted
    }
    pub const fn accepted_transport(&self) -> Option<Transport> {
        self.accepted_transport
    }
    pub fn response(&self) -> Option<&ResponseMetadata> {
        self.response.as_ref()
    }
}

/// One captured frame this operation could not correlate to its query.
///
/// There is no transport field: DNS-over-TCP runs on a kernel socket and never
/// yields captured frames, so undecoded evidence is always UDP.
#[derive(Clone, Debug)]
pub struct UndecodedEvidence {
    pub attempt: u32,
    pub frame: Frame,
}

/// Collected DNS output. Summary metadata has the same owner as streamed
/// completion; attempts and records are retained only for an aggregate run.
#[derive(Clone, Debug)]
pub struct Report {
    summary: Summary,
    response: Option<ValidatedResponse>,
    attempts: Vec<AttemptEvidence>,
    undecoded: Vec<UndecodedEvidence>,
    diagnostics: Vec<Diagnostic>,
}

impl Report {
    pub fn new(
        summary: Summary,
        response: Option<ValidatedResponse>,
        attempts: Vec<AttemptEvidence>,
        undecoded: Vec<UndecodedEvidence>,
        diagnostics: Vec<Diagnostic>,
    ) -> Result<Self, EvidenceError> {
        summary.completion.validate()?;
        if summary.completion.response() != response.as_ref().map(|response| &response.metadata) {
            return Err(EvidenceError(
                "retained response must match the accepted response header",
            ));
        }
        if summary.completion.fallback_attempted()
            != attempts
                .iter()
                .any(|attempt| attempt.transport() == Transport::Tcp)
        {
            return Err(EvidenceError(
                "fallback must agree with retained TCP attempts",
            ));
        }
        Ok(Self {
            summary,
            response,
            attempts,
            undecoded,
            diagnostics,
        })
    }
    pub fn summary(&self) -> &Summary {
        &self.summary
    }
    pub fn response(&self) -> Option<&ValidatedResponse> {
        self.response.as_ref()
    }
    pub fn attempts(&self) -> &[AttemptEvidence] {
        &self.attempts
    }
    pub fn undecoded(&self) -> &[UndecodedEvidence] {
        &self.undecoded
    }
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
    /// Separates the completed operation from its retained evidence without
    /// copying captured bytes or record collections.
    pub fn into_parts(
        self,
    ) -> (
        Summary,
        Option<ValidatedResponse>,
        Vec<AttemptEvidence>,
        Vec<UndecodedEvidence>,
        Vec<Diagnostic>,
    ) {
        (
            self.summary,
            self.response,
            self.attempts,
            self.undecoded,
            self.diagnostics,
        )
    }
}

#[derive(Clone, Debug)]
pub struct EventContext {
    pub server: Arc<str>,
    pub server_port: u16,
    pub query_name: Arc<str>,
    pub query_type: QueryType,
}

#[derive(Clone, Debug)]
pub enum Event {
    Attempt {
        context: Arc<EventContext>,
        evidence: AttemptEvidence,
    },
    Record {
        attempt: u32,
        transport: Transport,
        context: Arc<EventContext>,
        section: Section,
        record: Record,
    },
    Rejected {
        attempt: u32,
        transport: Transport,
        context: Arc<EventContext>,
        record: RejectedRecord,
    },
    Undecoded(UndecodedEvidence),
    Diagnostic(Diagnostic),
}

/// Final DNS metadata after every attempt and record event was published.
/// Diagnostics are not repeated here: each one already reached the caller as
/// [`Event::Diagnostic`] when it was raised.
#[derive(Clone, Debug)]
pub struct Summary {
    pub server: String,
    pub server_port: u16,
    pub resolved_addresses: Vec<IpAddr>,
    pub query_name: String,
    pub query_type: QueryType,
    pub transaction_id: u16,
    pub completion: Completion,
    pub stats: Stats,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One vocabulary: what the CLI prints for an attempt is what the JSON
    /// document calls it.
    #[test]
    fn outcome_names_match_the_serialized_names() {
        for outcome in [
            Outcome::Response,
            Outcome::Truncated,
            Outcome::Timeout,
            Outcome::Unrelated,
            Outcome::DecodeFailure,
            Outcome::NetworkFailure,
        ] {
            let serialized = serde_json::to_value(outcome).expect("outcome is a name");
            assert_eq!(serialized.as_str(), Some(outcome.as_str()));
        }

        for transport in [Transport::Udp, Transport::Tcp] {
            let serialized = serde_json::to_value(transport).expect("transport is a name");
            assert_eq!(serialized.as_str(), Some(transport.as_str()));
        }
    }
}
