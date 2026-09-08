// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    DecodeError,
    name::{self, MAX_LABEL_LEN, MAX_NAME_LEN},
};
use bytes::Bytes;
use serde::Serialize;
use std::fmt::{self, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};

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

    pub fn from_labels<I, B>(labels: I) -> Result<Self, DecodeError>
    where
        I: IntoIterator<Item = B>,
        B: Into<Bytes>,
    {
        let mut bounded = Vec::new();
        let mut wire_length = 1usize;
        for label in labels {
            let label = label.into();
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(DecodeError::InvalidName {
                    message: format!("wire labels must contain 1..={MAX_LABEL_LEN} octets"),
                });
            }
            wire_length = wire_length
                .checked_add(label.len() + 1)
                .ok_or(name::Error::NameTooLong)?;
            if wire_length > MAX_NAME_LEN {
                return Err(name::Error::NameTooLong.into());
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
