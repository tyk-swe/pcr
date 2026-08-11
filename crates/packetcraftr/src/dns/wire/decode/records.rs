// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS resource-record, RDATA, and EDNS decoding.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::super::super::DNS_TYPE_OPT;
use super::super::super::error::DnsWireError;
use super::super::super::model::{
    DnsEdns, DnsEdnsOption, DnsLimits, DnsName, DnsRecord, DnsRecordValue,
};
use super::super::name::decode_name;
use super::primitives::{read_u16, read_u32};

pub(super) fn decode_records(
    message: &[u8],
    mut offset: usize,
    count: usize,
    limits: DnsLimits,
) -> Result<(Vec<DnsRecord>, usize), DnsWireError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let (owner, next) = decode_name(message, offset, limits)?;
        offset = next;
        let type_code = read_u16(message, offset, "record type")?;
        let class = read_u16(message, offset + 2, "record class")?;
        let ttl = read_u32(message, offset + 4, "record TTL")?;
        let rdata_length = usize::from(read_u16(message, offset + 8, "RDATA length")?);
        let rdata_offset = offset + 10;
        let rdata_end =
            rdata_offset
                .checked_add(rdata_length)
                .ok_or(DnsWireError::TruncatedField {
                    field: "RDATA",
                    offset: rdata_offset,
                })?;
        message
            .get(rdata_offset..rdata_end)
            .ok_or(DnsWireError::TruncatedField {
                field: "RDATA",
                offset: rdata_offset,
            })?;
        let value = decode_rdata(
            message,
            type_code,
            class,
            ttl,
            rdata_offset,
            rdata_end,
            limits,
        )?;
        records.push(DnsRecord {
            owner,
            class,
            ttl,
            value,
        });
        offset = rdata_end;
    }
    Ok((records, offset))
}

fn decode_rdata(
    message: &[u8],
    type_code: u16,
    class: u16,
    ttl: u32,
    offset: usize,
    end: usize,
    limits: DnsLimits,
) -> Result<DnsRecordValue, DnsWireError> {
    let rdata = message
        .get(offset..end)
        .ok_or(DnsWireError::TruncatedField {
            field: "RDATA",
            offset,
        })?;
    let invalid = |message: &str| DnsWireError::InvalidRdata {
        record_type: type_code,
        offset,
        message: message.to_owned(),
    };
    let exact_name = |start| -> Result<DnsName, DnsWireError> {
        let (name, next) = decode_name(message, start, limits)?;
        if next != end {
            return Err(invalid("name does not consume the declared RDATA"));
        }
        Ok(name)
    };
    match type_code {
        1 => {
            let bytes: [u8; 4] = rdata
                .try_into()
                .map_err(|_| invalid("A RDATA must be 4 bytes"))?;
            Ok(DnsRecordValue::A(Ipv4Addr::from(bytes)))
        }
        2 => Ok(DnsRecordValue::Ns(exact_name(offset)?)),
        5 => Ok(DnsRecordValue::Cname(exact_name(offset)?)),
        6 => {
            let (primary_name_server, next) = decode_name(message, offset, limits)?;
            let (responsible_mailbox, next) = decode_name(message, next, limits)?;
            if next.checked_add(20) != Some(end) {
                return Err(invalid("SOA RDATA must end with five 32-bit integers"));
            }
            Ok(DnsRecordValue::Soa {
                primary_name_server,
                responsible_mailbox,
                serial: read_u32(message, next, "SOA serial")?,
                refresh: read_u32(message, next + 4, "SOA refresh")?,
                retry: read_u32(message, next + 8, "SOA retry")?,
                expire: read_u32(message, next + 12, "SOA expire")?,
                minimum: read_u32(message, next + 16, "SOA minimum")?,
            })
        }
        12 => Ok(DnsRecordValue::Ptr(exact_name(offset)?)),
        15 => {
            if rdata.len() < 3 {
                return Err(invalid("MX RDATA is shorter than preference plus name"));
            }
            let preference = read_u16(message, offset, "MX preference")?;
            let (exchange, next) = decode_name(message, offset + 2, limits)?;
            if next != end {
                return Err(invalid("MX name does not consume the declared RDATA"));
            }
            Ok(DnsRecordValue::Mx {
                preference,
                exchange,
            })
        }
        16 => {
            let mut cursor = 0usize;
            let mut strings = Vec::new();
            let mut total = 0usize;
            while cursor < rdata.len() {
                if strings.len() >= limits.max_txt_strings {
                    return Err(DnsWireError::TxtStringLimit {
                        limit: limits.max_txt_strings,
                    });
                }
                let length = usize::from(rdata[cursor]);
                cursor += 1;
                let string = rdata
                    .get(cursor..cursor.saturating_add(length))
                    .ok_or_else(|| invalid("TXT character-string exceeds declared RDATA"))?;
                total = total
                    .checked_add(length)
                    .ok_or(DnsWireError::TxtByteLimit {
                        limit: limits.max_txt_bytes,
                    })?;
                if total > limits.max_txt_bytes {
                    return Err(DnsWireError::TxtByteLimit {
                        limit: limits.max_txt_bytes,
                    });
                }
                strings.push(Bytes::copy_from_slice(string));
                cursor += length;
            }
            Ok(DnsRecordValue::Txt(strings))
        }
        28 => {
            let bytes: [u8; 16] = rdata
                .try_into()
                .map_err(|_| invalid("AAAA RDATA must be 16 bytes"))?;
            Ok(DnsRecordValue::Aaaa(Ipv6Addr::from(bytes)))
        }
        33 => {
            if rdata.len() < 7 {
                return Err(invalid(
                    "SRV RDATA is shorter than priority, weight, port, and name",
                ));
            }
            let priority = read_u16(message, offset, "SRV priority")?;
            let weight = read_u16(message, offset + 2, "SRV weight")?;
            let port = read_u16(message, offset + 4, "SRV port")?;
            let (target, next) = decode_name(message, offset + 6, limits)?;
            if next != end {
                return Err(invalid("SRV name does not consume the declared RDATA"));
            }
            Ok(DnsRecordValue::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        DNS_TYPE_OPT => decode_edns(class, ttl, rdata).map(DnsRecordValue::Opt),
        _ => Ok(DnsRecordValue::Unknown {
            type_code,
            rdata: Bytes::copy_from_slice(rdata),
        }),
    }
}

fn decode_edns(class: u16, ttl: u32, rdata: &[u8]) -> Result<DnsEdns, DnsWireError> {
    let extended_response_code = (ttl >> 24) as u8;
    let version = ((ttl >> 16) & 0xff) as u8;
    if version != 0 {
        return Err(DnsWireError::UnsupportedEdnsVersion { version });
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "an OPT record packs the extended rcode and version in the high half of the TTL \
                  field; the low 16 bits are the flags this reads"
    )]
    let flags = ttl as u16;
    let mut options = Vec::new();
    let mut cursor = 0usize;
    while cursor < rdata.len() {
        let header = rdata.get(cursor..cursor.saturating_add(4)).ok_or_else(|| {
            DnsWireError::InvalidEdns {
                message: format!("option header is truncated at RDATA byte {cursor}"),
            }
        })?;
        let code = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        cursor += 4;
        let data = rdata
            .get(cursor..cursor.saturating_add(length))
            .ok_or_else(|| DnsWireError::InvalidEdns {
                message: format!("option {code} data is truncated"),
            })?;
        options.push(DnsEdnsOption {
            code,
            data: Bytes::copy_from_slice(data),
        });
        cursor += length;
    }
    Ok(DnsEdns {
        udp_payload_size: class,
        extended_response_code,
        version,
        dnssec_ok: flags & 0x8000 != 0,
        flags,
        options,
    })
}
