// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS record, EDNS, and section output contracts.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use super::super::hex::compact_hex;

/// Output-v1 DNS section.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

impl From<crate::dns::Section> for Section {
    fn from(value: crate::dns::Section) -> Self {
        match value {
            crate::dns::Section::Answer => Self::Answer,
            crate::dns::Section::Authority => Self::Authority,
            crate::dns::Section::Additional => Self::Additional,
        }
    }
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

/// Typed DNS record data; unknown records preserve exact RDATA as hexadecimal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecordData {
    A {
        address: Ipv4Addr,
    },
    Aaaa {
        address: Ipv6Addr,
    },
    Cname {
        canonical_name: String,
    },
    Mx {
        preference: u16,
        exchange: String,
    },
    Ns {
        name_server: String,
    },
    Ptr {
        pointer: String,
    },
    Soa {
        primary_name_server: String,
        responsible_mailbox: String,
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
        target: String,
    },
    Txt {
        /// UTF-8 display projections. `strings_hex` remains the exact value.
        strings: Vec<String>,
        strings_hex: Vec<String>,
    },
    Opt {
        edns: Edns,
    },
    Unknown {
        type_code: u16,
        rdata_hex: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EdnsOption {
    pub code: u16,
    pub data_hex: String,
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

impl From<crate::dns::Edns> for Edns {
    fn from(value: crate::dns::Edns) -> Self {
        Self {
            udp_payload_size: value.udp_payload_size,
            extended_response_code: value.extended_response_code,
            version: value.version,
            dnssec_ok: value.dnssec_ok,
            flags: value.flags,
            options: value.options.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<crate::dns::EdnsOption> for EdnsOption {
    fn from(value: crate::dns::EdnsOption) -> Self {
        Self {
            code: value.code,
            data_hex: compact_hex(&value.data),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Record {
    pub owner: String,
    pub class: u16,
    pub ttl: u32,
    #[serde(flatten)]
    pub data: RecordData,
}

impl Record {
    pub(super) fn from_record(record: crate::dns::Record) -> Self {
        let data = match record.value {
            crate::dns::RecordValue::A(address) => RecordData::A { address },
            crate::dns::RecordValue::Aaaa(address) => RecordData::Aaaa { address },
            crate::dns::RecordValue::Cname(canonical_name) => RecordData::Cname {
                canonical_name: canonical_name.to_string(),
            },
            crate::dns::RecordValue::Mx {
                preference,
                exchange,
            } => RecordData::Mx {
                preference,
                exchange: exchange.to_string(),
            },
            crate::dns::RecordValue::Ns(name_server) => RecordData::Ns {
                name_server: name_server.to_string(),
            },
            crate::dns::RecordValue::Ptr(pointer) => RecordData::Ptr {
                pointer: pointer.to_string(),
            },
            crate::dns::RecordValue::Soa {
                primary_name_server,
                responsible_mailbox,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => RecordData::Soa {
                primary_name_server: primary_name_server.to_string(),
                responsible_mailbox: responsible_mailbox.to_string(),
                serial,
                refresh,
                retry,
                expire,
                minimum,
            },
            crate::dns::RecordValue::Srv {
                priority,
                weight,
                port,
                target,
            } => RecordData::Srv {
                priority,
                weight,
                port,
                target: target.to_string(),
            },
            crate::dns::RecordValue::Txt(strings) => RecordData::Txt {
                strings: strings
                    .iter()
                    .map(|value| String::from_utf8_lossy(value).into_owned())
                    .collect(),
                strings_hex: strings.iter().map(|value| compact_hex(value)).collect(),
            },
            crate::dns::RecordValue::Opt(edns) => RecordData::Opt { edns: edns.into() },
            crate::dns::RecordValue::Unknown { type_code, rdata } => RecordData::Unknown {
                type_code,
                rdata_hex: compact_hex(&rdata),
            },
        };
        Self {
            owner: record.owner.to_string(),
            class: record.class,
            ttl: record.ttl,
            data,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RejectedRecord {
    pub section: Section,
    pub index: usize,
    pub owner: String,
    pub type_code: u16,
    pub reason: String,
}
