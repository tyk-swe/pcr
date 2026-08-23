// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::Stats;

use super::super::DNS_TYPE_OPT;
use super::super::wire::WireError;
use super::super::wire::response_code_name;
use super::request::QueryType;

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

    pub fn from_labels<I, B>(labels: I) -> std::result::Result<Self, WireError>
    where
        I: IntoIterator<Item = B>,
        B: Into<Bytes>,
    {
        let labels = labels.into_iter().map(Into::into).collect::<Vec<_>>();
        let mut wire_length = 1usize;
        for label in &labels {
            if label.is_empty() || label.len() > 63 {
                return Err(WireError::InvalidName {
                    message: "wire labels must contain 1..=63 octets".to_owned(),
                });
            }
            wire_length = wire_length
                .checked_add(label.len() + 1)
                .ok_or(WireError::NameTooLong)?;
        }
        if wire_length > 255 {
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
                    formatter.write_str(&char::from(*byte).to_string())?;
                } else {
                    write!(formatter, "\\{byte:03}")?;
                }
            }
        }
        formatter.write_str(".")
    }
}

impl Serialize for Name {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
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
            Self::Opt(_) => DNS_TYPE_OPT,
            Self::Unknown { type_code, .. } => *type_code,
        }
    }

    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::A(_) => "a",
            Self::Aaaa(_) => "aaaa",
            Self::Cname(_) => "cname",
            Self::Mx { .. } => "mx",
            Self::Ns(_) => "ns",
            Self::Ptr(_) => "ptr",
            Self::Soa { .. } => "soa",
            Self::Srv { .. } => "srv",
            Self::Txt(_) => "txt",
            Self::Opt(_) => "opt",
            Self::Unknown { .. } => "unknown",
        }
    }

    pub(in crate::dns) fn referenced_name(&self) -> Option<&Name> {
        match self {
            Self::Cname(value) | Self::Ns(value) => Some(value),
            Self::Mx { exchange, .. } => Some(exchange),
            Self::Srv { target, .. } => Some(target),
            Self::A(_)
            | Self::Aaaa(_)
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

#[derive(Clone, Debug)]
pub struct AttemptEvidence {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub source_port: u16,
    pub status: Outcome,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<Frame>,
    pub response_code: Option<u16>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct UndecodedEvidence {
    pub attempt: u32,
    pub frame: Frame,
}

#[derive(Clone, Debug)]
pub struct Result {
    pub server: String,
    pub server_port: u16,
    pub resolved_addresses: Vec<IpAddr>,
    pub query_name: String,
    pub query_type: QueryType,
    pub transaction_id: u16,
    pub outcome: Outcome,
    pub response: Option<ValidatedResponse>,
    pub attempts: Vec<AttemptEvidence>,
    pub undecoded: Vec<UndecodedEvidence>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
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
        context: Arc<EventContext>,
        section: Section,
        record: Record,
    },
    Rejected {
        attempt: u32,
        context: Arc<EventContext>,
        record: RejectedRecord,
    },
    Undecoded(UndecodedEvidence),
    Diagnostic(Diagnostic),
}

#[derive(Clone, Debug)]
pub struct Summary {
    pub server: String,
    pub server_port: u16,
    pub resolved_addresses: Vec<IpAddr>,
    pub query_name: String,
    pub query_type: QueryType,
    pub transaction_id: u16,
    pub outcome: Outcome,
    pub response: Option<ResponseMetadata>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}
