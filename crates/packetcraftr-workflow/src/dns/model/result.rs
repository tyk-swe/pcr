// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::Serialize;

use packetcraftr_capture::Frame;
use packetcraftr_packet::diagnostic::Diagnostic;

use crate::Stats;

use super::super::DNS_TYPE_OPT;
use super::super::error::DnsWireError;
use super::super::wire::response_code_name;
use super::request::DnsQueryType;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSection {
    Answer,
    Authority,
    Additional,
}

/// A lossless DNS wire name. Labels retain their exact octets; DNS semantic
/// equality folds ASCII letters only, and presentation escaping is deferred
/// to [`fmt::Display`].
#[derive(Clone, Debug, Eq)]
pub struct DnsName {
    pub(in crate::dns) labels: Vec<Bytes>,
}

impl DnsName {
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

    pub fn from_labels<I, B>(labels: I) -> std::result::Result<Self, DnsWireError>
    where
        I: IntoIterator<Item = B>,
        B: Into<Bytes>,
    {
        let labels = labels.into_iter().map(Into::into).collect::<Vec<_>>();
        let mut wire_length = 1usize;
        for label in &labels {
            if label.is_empty() || label.len() > 63 {
                return Err(DnsWireError::InvalidName {
                    message: "wire labels must contain 1..=63 octets".to_owned(),
                });
            }
            wire_length = wire_length
                .checked_add(label.len() + 1)
                .ok_or(DnsWireError::NameTooLong)?;
        }
        if wire_length > 255 {
            return Err(DnsWireError::NameTooLong);
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

impl PartialEq for DnsName {
    fn eq(&self, other: &Self) -> bool {
        self.labels.len() == other.labels.len()
            && self
                .labels
                .iter()
                .zip(&other.labels)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
    }
}

impl fmt::Display for DnsName {
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

impl Serialize for DnsName {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsEdnsOption {
    pub code: u16,
    pub data: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsEdns {
    pub udp_payload_size: u16,
    pub extended_response_code: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    pub flags: u16,
    pub options: Vec<DnsEdnsOption>,
}

impl fmt::Display for DnsSection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Answer => "answer",
            Self::Authority => "authority",
            Self::Additional => "additional",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsRecordValue {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(DnsName),
    Mx {
        preference: u16,
        exchange: DnsName,
    },
    Ns(DnsName),
    Ptr(DnsName),
    Soa {
        primary_name_server: DnsName,
        responsible_mailbox: DnsName,
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
        target: DnsName,
    },
    Txt(Vec<Bytes>),
    Opt(DnsEdns),
    Unknown {
        type_code: u16,
        rdata: Bytes,
    },
}

impl DnsRecordValue {
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

    pub(in crate::dns) fn referenced_name(&self) -> Option<&DnsName> {
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
pub struct DnsRecord {
    pub owner: DnsName,
    pub class: u16,
    pub ttl: u32,
    pub value: DnsRecordValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRejectedRecord {
    pub section: DnsSection,
    pub index: usize,
    pub owner: String,
    pub type_code: u16,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedDnsResponse {
    pub transaction_id: u16,
    pub response_code: u16,
    pub edns: Option<DnsEdns>,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub rejected_records: Vec<DnsRejectedRecord>,
    pub rejected_record_count: usize,
}

impl ValidatedDnsResponse {
    pub fn response_code_name(&self) -> &'static str {
        response_code_name(self.response_code)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsOutcome {
    Response,
    Truncated,
    Timeout,
    Unrelated,
    DecodeFailure,
    NetworkFailure,
}

#[derive(Clone, Debug)]
pub struct DnsAttemptEvidence {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub source_port: u16,
    pub status: DnsOutcome,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<Frame>,
    pub response_code: Option<u16>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct DnsUndecodedEvidence {
    pub attempt: u32,
    pub frame: Frame,
}

#[derive(Clone, Debug)]
pub struct DnsResult {
    pub server: String,
    pub server_port: u16,
    pub resolved_addresses: Vec<IpAddr>,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub transaction_id: u16,
    pub outcome: DnsOutcome,
    pub response: Option<ValidatedDnsResponse>,
    pub attempts: Vec<DnsAttemptEvidence>,
    pub undecoded: Vec<DnsUndecodedEvidence>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}
