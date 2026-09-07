// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS record, EDNS, and section output contracts.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::output::hex::compact_hex;

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
    Caa {
        flags: u8,
        /// UTF-8 display projection. `tag_hex` remains the exact value.
        tag: String,
        tag_hex: String,
        /// UTF-8 display projection. `value_hex` remains the exact value.
        value: String,
        value_hex: String,
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

impl From<packetcraftr::dns::Edns> for Edns {
    fn from(value: packetcraftr::dns::Edns) -> Self {
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

impl From<packetcraftr::dns::EdnsOption> for EdnsOption {
    fn from(value: packetcraftr::dns::EdnsOption) -> Self {
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
    pub(super) fn from_record(record: packetcraftr::dns::Record) -> Self {
        let data = match record.value {
            packetcraftr::dns::RecordValue::A(address) => RecordData::A { address },
            packetcraftr::dns::RecordValue::Aaaa(address) => RecordData::Aaaa { address },
            packetcraftr::dns::RecordValue::Caa { flags, tag, value } => RecordData::Caa {
                flags,
                tag: String::from_utf8_lossy(&tag).into_owned(),
                tag_hex: compact_hex(&tag),
                value: String::from_utf8_lossy(&value).into_owned(),
                value_hex: compact_hex(&value),
            },
            packetcraftr::dns::RecordValue::Cname(canonical_name) => RecordData::Cname {
                canonical_name: canonical_name.to_string(),
            },
            packetcraftr::dns::RecordValue::Mx {
                preference,
                exchange,
            } => RecordData::Mx {
                preference,
                exchange: exchange.to_string(),
            },
            packetcraftr::dns::RecordValue::Ns(name_server) => RecordData::Ns {
                name_server: name_server.to_string(),
            },
            packetcraftr::dns::RecordValue::Ptr(pointer) => RecordData::Ptr {
                pointer: pointer.to_string(),
            },
            packetcraftr::dns::RecordValue::Soa {
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
            packetcraftr::dns::RecordValue::Srv {
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
            packetcraftr::dns::RecordValue::Txt(strings) => RecordData::Txt {
                strings: strings
                    .iter()
                    .map(|value| String::from_utf8_lossy(value).into_owned())
                    .collect(),
                strings_hex: strings.iter().map(|value| compact_hex(value)).collect(),
            },
            packetcraftr::dns::RecordValue::Opt(edns) => RecordData::Opt { edns: edns.into() },
            packetcraftr::dns::RecordValue::Unknown { type_code, rdata } => RecordData::Unknown {
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
