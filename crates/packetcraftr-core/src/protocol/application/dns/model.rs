// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use serde::Serialize;
use std::fmt::{self, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{Error, MAX_LABEL_LEN, MAX_NAME_LEN};
use crate::field::WireValue;

/// The bounded, exact DNS-over-UDP layer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dns {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub authoritative_answer: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub rcode: u8,
    pub question_count: WireValue<u16>,
    pub answer_count: WireValue<u16>,
    pub authority_count: WireValue<u16>,
    pub additional_count: WireValue<u16>,
    pub questions: Vec<Question>,
    /// Reserved header bit retained for protocol fixtures.
    pub reserved: bool,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub(super) wire: Bytes,
}

impl Dns {
    /// Returns the complete original DNS payload, including opaque records.
    pub fn wire(&self) -> &Bytes {
        &self.wire
    }

    /// Begins an explicit edit, deriving section counts from the new record sets.
    pub fn edit(&mut self, edit: impl FnOnce(&mut Self)) {
        self.wire = Bytes::new();
        self.question_count = WireValue::Auto;
        self.answer_count = WireValue::Auto;
        self.authority_count = WireValue::Auto;
        self.additional_count = WireValue::Auto;
        edit(self);
    }
}

/// A lossless DNS wire name. Labels retain their exact octets; DNS semantic
/// equality folds ASCII letters only, and presentation escaping is deferred
/// to [`fmt::Display`].
#[derive(Clone, Debug, Eq)]
pub struct Name {
    pub(super) labels: Vec<Bytes>,
}

impl Name {
    pub fn root() -> Self {
        Self { labels: Vec::new() }
    }

    pub fn from_labels<I, B>(labels: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = B>,
        B: Into<Bytes>,
    {
        let mut bounded = Vec::new();
        let mut wire_length = 1usize;
        for label in labels {
            let label = label.into();
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(Error::InvalidName {
                    message: format!("wire labels must contain 1..={MAX_LABEL_LEN} octets"),
                });
            }
            wire_length = wire_length
                .checked_add(label.len() + 1)
                .ok_or(Error::NameTooLong)?;
            if wire_length > MAX_NAME_LEN {
                return Err(Error::NameTooLong);
            }
            bounded.push(label);
        }
        Ok(Self { labels: bounded })
    }

    pub fn labels(&self) -> &[Bytes] {
        &self.labels
    }

    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }
}

impl std::str::FromStr for Name {
    type Err = Error;

    /// Parses presentation names, including `\\DDD` escaped label octets.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let invalid = || Error::InvalidName {
            message: "invalid DNS presentation name".to_owned(),
        };
        if input == "." {
            return Ok(Self::root());
        }
        if input.is_empty() || input.len() > 1020 {
            return Err(invalid());
        }
        let mut labels = Vec::new();
        let mut label = Vec::new();
        let mut bytes = input.bytes();
        while let Some(byte) = bytes.next() {
            match byte {
                b'.' => {
                    if label.is_empty() {
                        return Err(invalid());
                    }
                    labels.push(Bytes::from(std::mem::take(&mut label)));
                }
                b'\\' => {
                    let next = bytes.next().ok_or_else(invalid)?;
                    if next.is_ascii_digit() {
                        let second = bytes
                            .next()
                            .filter(u8::is_ascii_digit)
                            .ok_or_else(invalid)?;
                        let third = bytes
                            .next()
                            .filter(u8::is_ascii_digit)
                            .ok_or_else(invalid)?;
                        let value = u16::from(next - b'0') * 100
                            + u16::from(second - b'0') * 10
                            + u16::from(third - b'0');
                        label.push(u8::try_from(value).map_err(|_| invalid())?);
                    } else {
                        label.push(next);
                    }
                }
                _ => label.push(byte),
            }
            if label.len() > MAX_LABEL_LEN || labels.len() > 127 {
                return Err(invalid());
            }
        }
        if !label.is_empty() {
            labels.push(Bytes::from(label));
        }
        Self::from_labels(labels)
    }
}

/// One DNS question with a lossless owner name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub query_type: u16,
    pub class: u16,
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

impl Edns {
    pub(super) fn record_ttl(&self) -> u32 {
        u32::from(self.extended_response_code) << 24
            | u32::from(self.version) << 16
            | u32::from(self.flags)
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
            Self::Opt(_) => 41,
            Self::Unknown { type_code, .. } => *type_code,
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

impl Record {
    /// Constructs a root-owner OPT record with matching class/TTL metadata.
    pub fn opt(edns: Edns) -> Self {
        Self {
            owner: Name::root(),
            class: edns.udp_payload_size,
            ttl: edns.record_ttl(),
            value: RecordValue::Opt(edns),
        }
    }
}
