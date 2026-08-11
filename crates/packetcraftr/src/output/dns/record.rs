// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS record, EDNS, and section output contracts.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::dns::{
    Edns as DnsEdns, EdnsOption as DnsEdnsOption, Record as DnsRecord,
    RecordValue as DnsRecordValue,
};
use serde::Serialize;

use super::super::hex::compact_hex;

/// Output-v1 DNS section.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSection {
    Answer,
    Authority,
    Additional,
}

impl From<crate::dns::Section> for DnsSection {
    fn from(value: crate::dns::Section) -> Self {
        match value {
            crate::dns::Section::Answer => Self::Answer,
            crate::dns::Section::Authority => Self::Authority,
            crate::dns::Section::Additional => Self::Additional,
        }
    }
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

/// Typed DNS record data; unknown records preserve exact RDATA as hexadecimal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DnsRecordData {
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
        edns: DnsEdnsOutput,
    },
    Unknown {
        type_code: u16,
        rdata_hex: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsEdnsOptionOutput {
    pub code: u16,
    pub data_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsEdnsOutput {
    pub udp_payload_size: u16,
    pub extended_response_code: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    pub flags: u16,
    pub options: Vec<DnsEdnsOptionOutput>,
}

impl From<DnsEdns> for DnsEdnsOutput {
    fn from(value: DnsEdns) -> Self {
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

impl From<DnsEdnsOption> for DnsEdnsOptionOutput {
    fn from(value: DnsEdnsOption) -> Self {
        Self {
            code: value.code,
            data_hex: compact_hex(&value.data),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRecordOutput {
    pub owner: String,
    pub class: u16,
    pub ttl: u32,
    #[serde(flatten)]
    pub data: DnsRecordData,
}

impl DnsRecordOutput {
    pub(super) fn from_record(record: DnsRecord) -> Self {
        let data = match record.value {
            DnsRecordValue::A(address) => DnsRecordData::A { address },
            DnsRecordValue::Aaaa(address) => DnsRecordData::Aaaa { address },
            DnsRecordValue::Cname(canonical_name) => DnsRecordData::Cname {
                canonical_name: canonical_name.to_string(),
            },
            DnsRecordValue::Mx {
                preference,
                exchange,
            } => DnsRecordData::Mx {
                preference,
                exchange: exchange.to_string(),
            },
            DnsRecordValue::Ns(name_server) => DnsRecordData::Ns {
                name_server: name_server.to_string(),
            },
            DnsRecordValue::Ptr(pointer) => DnsRecordData::Ptr {
                pointer: pointer.to_string(),
            },
            DnsRecordValue::Soa {
                primary_name_server,
                responsible_mailbox,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => DnsRecordData::Soa {
                primary_name_server: primary_name_server.to_string(),
                responsible_mailbox: responsible_mailbox.to_string(),
                serial,
                refresh,
                retry,
                expire,
                minimum,
            },
            DnsRecordValue::Srv {
                priority,
                weight,
                port,
                target,
            } => DnsRecordData::Srv {
                priority,
                weight,
                port,
                target: target.to_string(),
            },
            DnsRecordValue::Txt(strings) => DnsRecordData::Txt {
                strings: strings
                    .iter()
                    .map(|value| String::from_utf8_lossy(value).into_owned())
                    .collect(),
                strings_hex: strings.iter().map(|value| compact_hex(value)).collect(),
            },
            DnsRecordValue::Opt(edns) => DnsRecordData::Opt { edns: edns.into() },
            DnsRecordValue::Unknown { type_code, rdata } => DnsRecordData::Unknown {
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
pub struct DnsRejectedRecordOutput {
    pub section: DnsSection,
    pub index: usize,
    pub owner: String,
    pub type_code: u16,
    pub reason: String,
}
