// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS resource-record, RDATA, and EDNS decoding.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::super::super::DNS_TYPE_OPT;
use super::super::super::error::WireError;
use super::super::super::model::{Edns, EdnsOption, Limits, Name, Record, RecordValue};
use super::super::name::decode_name;
use super::primitives::{read_u16, read_u32};

pub(super) fn decode_records(
    message: &[u8],
    mut offset: usize,
    count: usize,
    limits: Limits,
) -> Result<(Vec<Record>, usize), WireError> {
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
                .ok_or(WireError::TruncatedField {
                    field: "RDATA",
                    offset: rdata_offset,
                })?;
        message
            .get(rdata_offset..rdata_end)
            .ok_or(WireError::TruncatedField {
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
        records.push(Record {
            owner,
            class,
            ttl,
            value,
        });
        offset = rdata_end;
    }
    Ok((records, offset))
}

struct Rdata<'a> {
    message: &'a [u8],
    bytes: &'a [u8],
    type_code: u16,
    offset: usize,
    end: usize,
    limits: Limits,
}

impl Rdata<'_> {
    fn invalid(&self, message: &str) -> WireError {
        WireError::InvalidRdata {
            record_type: self.type_code,
            offset: self.offset,
            message: message.to_owned(),
        }
    }

    fn exact_name(&self, start: usize) -> Result<Name, WireError> {
        let (name, next) = decode_name(self.message, start, self.limits)?;
        if next != self.end {
            return Err(self.invalid("name does not consume the declared RDATA"));
        }
        Ok(name)
    }

    fn decode_soa(&self) -> Result<RecordValue, WireError> {
        let (primary_name_server, next) = decode_name(self.message, self.offset, self.limits)?;
        let (responsible_mailbox, next) = decode_name(self.message, next, self.limits)?;
        if next.checked_add(20) != Some(self.end) {
            return Err(self.invalid("SOA RDATA must end with five 32-bit integers"));
        }
        Ok(RecordValue::Soa {
            primary_name_server,
            responsible_mailbox,
            serial: read_u32(self.message, next, "SOA serial")?,
            refresh: read_u32(self.message, next + 4, "SOA refresh")?,
            retry: read_u32(self.message, next + 8, "SOA retry")?,
            expire: read_u32(self.message, next + 12, "SOA expire")?,
            minimum: read_u32(self.message, next + 16, "SOA minimum")?,
        })
    }

    fn decode_mx(&self) -> Result<RecordValue, WireError> {
        if self.bytes.len() < 3 {
            return Err(self.invalid("MX RDATA is shorter than preference plus name"));
        }
        let preference = read_u16(self.message, self.offset, "MX preference")?;
        let (exchange, next) = decode_name(self.message, self.offset + 2, self.limits)?;
        if next != self.end {
            return Err(self.invalid("MX name does not consume the declared RDATA"));
        }
        Ok(RecordValue::Mx {
            preference,
            exchange,
        })
    }

    fn decode_txt(&self) -> Result<RecordValue, WireError> {
        let mut cursor = 0usize;
        let mut strings = Vec::new();
        let mut total = 0usize;
        while cursor < self.bytes.len() {
            if strings.len() >= self.limits.max_txt_strings {
                return Err(WireError::TxtStringLimit {
                    limit: self.limits.max_txt_strings,
                });
            }
            let length = usize::from(self.bytes[cursor]);
            cursor += 1;
            let string = self
                .bytes
                .get(cursor..cursor.saturating_add(length))
                .ok_or_else(|| self.invalid("TXT character-string exceeds declared RDATA"))?;
            total = total.checked_add(length).ok_or(WireError::TxtByteLimit {
                limit: self.limits.max_txt_bytes,
            })?;
            if total > self.limits.max_txt_bytes {
                return Err(WireError::TxtByteLimit {
                    limit: self.limits.max_txt_bytes,
                });
            }
            strings.push(Bytes::copy_from_slice(string));
            cursor += length;
        }
        Ok(RecordValue::Txt(strings))
    }

    fn decode_srv(&self) -> Result<RecordValue, WireError> {
        if self.bytes.len() < 7 {
            return Err(self.invalid("SRV RDATA is shorter than priority, weight, port, and name"));
        }
        let priority = read_u16(self.message, self.offset, "SRV priority")?;
        let weight = read_u16(self.message, self.offset + 2, "SRV weight")?;
        let port = read_u16(self.message, self.offset + 4, "SRV port")?;
        let (target, next) = decode_name(self.message, self.offset + 6, self.limits)?;
        if next != self.end {
            return Err(self.invalid("SRV name does not consume the declared RDATA"));
        }
        Ok(RecordValue::Srv {
            priority,
            weight,
            port,
            target,
        })
    }
}

fn decode_rdata(
    message: &[u8],
    type_code: u16,
    class: u16,
    ttl: u32,
    offset: usize,
    end: usize,
    limits: Limits,
) -> Result<RecordValue, WireError> {
    let bytes = message.get(offset..end).ok_or(WireError::TruncatedField {
        field: "RDATA",
        offset,
    })?;
    let rdata = Rdata {
        message,
        bytes,
        type_code,
        offset,
        end,
        limits,
    };
    match type_code {
        1 => {
            let bytes: [u8; 4] = bytes
                .try_into()
                .map_err(|_| rdata.invalid("A RDATA must be 4 bytes"))?;
            Ok(RecordValue::A(Ipv4Addr::from(bytes)))
        }
        2 => Ok(RecordValue::Ns(rdata.exact_name(offset)?)),
        5 => Ok(RecordValue::Cname(rdata.exact_name(offset)?)),
        6 => rdata.decode_soa(),
        12 => Ok(RecordValue::Ptr(rdata.exact_name(offset)?)),
        15 => rdata.decode_mx(),
        16 => rdata.decode_txt(),
        28 => {
            let bytes: [u8; 16] = bytes
                .try_into()
                .map_err(|_| rdata.invalid("AAAA RDATA must be 16 bytes"))?;
            Ok(RecordValue::Aaaa(Ipv6Addr::from(bytes)))
        }
        33 => rdata.decode_srv(),
        DNS_TYPE_OPT => decode_edns(class, ttl, bytes).map(RecordValue::Opt),
        _ => Ok(RecordValue::Unknown {
            type_code,
            rdata: Bytes::copy_from_slice(bytes),
        }),
    }
}

fn decode_edns(class: u16, ttl: u32, rdata: &[u8]) -> Result<Edns, WireError> {
    let ttl_bytes = ttl.to_be_bytes();
    let extended_response_code = ttl_bytes[0];
    let version = ttl_bytes[1];
    if version != 0 {
        return Err(WireError::UnsupportedEdnsVersion { version });
    }
    let flags = u16::from_be_bytes([ttl_bytes[2], ttl_bytes[3]]);
    let mut options = Vec::new();
    let mut cursor = 0usize;
    while cursor < rdata.len() {
        let header =
            rdata
                .get(cursor..cursor.saturating_add(4))
                .ok_or_else(|| WireError::InvalidEdns {
                    message: format!("option header is truncated at RDATA byte {cursor}"),
                })?;
        let code = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        cursor += 4;
        let data = rdata
            .get(cursor..cursor.saturating_add(length))
            .ok_or_else(|| WireError::InvalidEdns {
                message: format!("option {code} data is truncated"),
            })?;
        options.push(EdnsOption {
            code,
            data: Bytes::copy_from_slice(data),
        });
        cursor += length;
    }
    Ok(Edns {
        udp_payload_size: class,
        extended_response_code,
        version,
        dnssec_ok: flags & 0x8000 != 0,
        flags,
        options,
    })
}
