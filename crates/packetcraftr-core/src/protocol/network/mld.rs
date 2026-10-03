// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Multicast Listener Discovery (RFC 2710, RFC 3810) messages.
//!
//! The helpers read and write the body of an [`Icmpv6`] message, as
//! [`ndp`](super::ndp) does for Neighbor Discovery. Counts read from the wire
//! are checked against the bytes present and against [`MAX_RECORDS`] and
//! [`MAX_SOURCES`] before anything is allocated.
//! ```
//! use packetcraftr_core::protocol::network::mld::{Message, Mldv2Report, MulticastAddressRecord};
//!
//! let report = Mldv2Report {
//!     reserved: 0,
//!     records: vec![MulticastAddressRecord {
//!         record_type: 2,
//!         group: "ff02::1:ff00:1".parse()?,
//!         sources: vec!["2001:db8::1".parse()?],
//!         aux_data: Default::default(),
//!     }],
//! };
//! let icmp = report.to_icmpv6()?;
//! assert_eq!(icmp.icmp_type, 143);
//! assert_eq!(Message::from_icmpv6(&icmp)?, Message::Mldv2Report(report));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::net::Ipv6Addr;

use bytes::Bytes;

use crate::field::WireValue;

use super::Icmpv6;

pub const QUERY: u8 = 130;
pub const REPORT_V1: u8 = 131;
pub const DONE: u8 = 132;
pub const REPORT_V2: u8 = 143;

/// Most group records one MLDv2 report may carry.
pub const MAX_RECORDS: usize = 1024;
/// Most sources one MLDv2 query or group record may carry.
pub const MAX_SOURCES: usize = 1024;

const ADDRESS_LENGTH: usize = 16;
const MLDV1_LENGTH: usize = 20;
const MLDV2_QUERY_LENGTH: usize = 24;
const MLDV2_REPORT_LENGTH: usize = 4;
const RECORD_LENGTH: usize = 20;
/// Auxiliary data is sized in 32-bit words.
const AUX_UNIT: usize = 4;
const SUPPRESS_FLAG: u8 = 0x08;
const ROBUSTNESS_MASK: u8 = 0x07;
const QUERY_RESERVED_MAX: u8 = 0x0f;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("MLD message body is {actual} bytes; expected at least {expected}")]
    Truncated { expected: usize, actual: usize },
    #[error("{length} bytes follow the last MLD entry")]
    TrailingData { length: usize },
    #[error("ICMPv6 type {icmp_type} is not an MLD message")]
    UnsupportedType { icmp_type: u8 },
    #[error("MLD messages carry ICMPv6 code zero, not {code}")]
    Code { code: u8 },
    #[error("MLD {what} count {count} exceeds the limit of {limit}")]
    LimitExceeded {
        what: &'static str,
        count: usize,
        limit: usize,
    },
    #[error("MLD {field} value {value:#x} does not fit its bit width")]
    FieldRange { field: &'static str, value: u64 },
    #[error("MLD auxiliary data of {length} bytes is not a whole number of 32-bit words up to 255")]
    AuxiliaryLength { length: usize },
}

impl crate::error::Classified for Error {
    fn classification(&self) -> crate::error::Classification {
        crate::error::Classification::new(
            "packet.codec",
            crate::error::Kind::Packet,
            Some("correct the layer bytes or field values the codec refused"),
        )
    }
}

/// An MLD message decoded from an ICMPv6 type and body.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    Mldv1(Mldv1),
    Mldv2Query(Mldv2Query),
    Mldv2Report(Mldv2Report),
}

impl Message {
    /// Queries are told apart by length: 20 body bytes is MLDv1, 24 or more
    /// is MLDv2.
    pub fn from_icmpv6(icmp: &Icmpv6) -> Result<Self, Error> {
        if icmp.code != 0 {
            return Err(Error::Code { code: icmp.code });
        }
        match icmp.icmp_type {
            QUERY if icmp.body.len() > MLDV1_LENGTH => {
                Mldv2Query::decode(&icmp.body).map(Self::Mldv2Query)
            }
            QUERY => Mldv1::decode(Mldv1Kind::Query, &icmp.body).map(Self::Mldv1),
            REPORT_V1 => Mldv1::decode(Mldv1Kind::Report, &icmp.body).map(Self::Mldv1),
            DONE => Mldv1::decode(Mldv1Kind::Done, &icmp.body).map(Self::Mldv1),
            REPORT_V2 => Mldv2Report::decode(&icmp.body).map(Self::Mldv2Report),
            icmp_type => Err(Error::UnsupportedType { icmp_type }),
        }
    }

    pub fn to_icmpv6(&self) -> Result<Icmpv6, Error> {
        match self {
            Self::Mldv1(message) => message.to_icmpv6(),
            Self::Mldv2Query(message) => message.to_icmpv6(),
            Self::Mldv2Report(message) => message.to_icmpv6(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mldv1Kind {
    Query,
    Report,
    Done,
}

impl Mldv1Kind {
    pub const fn icmp_type(self) -> u8 {
        match self {
            Self::Query => QUERY,
            Self::Report => REPORT_V1,
            Self::Done => DONE,
        }
    }
}

/// An MLDv1 query, report or done message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mldv1 {
    pub kind: Mldv1Kind,
    /// Milliseconds; senders other than queriers set it to zero.
    pub max_response_delay: u16,
    pub reserved: u16,
    pub group: Ipv6Addr,
}

impl Mldv1 {
    pub fn decode(kind: Mldv1Kind, body: &[u8]) -> Result<Self, Error> {
        let Some(fixed) = body.first_chunk::<MLDV1_LENGTH>() else {
            return Err(truncated(MLDV1_LENGTH, body.len()));
        };
        no_trailing(body, MLDV1_LENGTH)?;
        Ok(Self {
            kind,
            max_response_delay: u16::from_be_bytes([fixed[0], fixed[1]]),
            reserved: u16::from_be_bytes([fixed[2], fixed[3]]),
            group: address(&fixed[4..]),
        })
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        let mut body = Vec::with_capacity(MLDV1_LENGTH);
        body.extend_from_slice(&self.max_response_delay.to_be_bytes());
        body.extend_from_slice(&self.reserved.to_be_bytes());
        body.extend_from_slice(&self.group.octets());
        Ok(Bytes::from(body))
    }

    pub fn to_icmpv6(&self) -> Result<Icmpv6, Error> {
        Ok(icmpv6(self.kind.icmp_type(), self.encode()?))
    }
}

/// An MLDv2 query: the MLDv1 fields plus robustness, interval and sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mldv2Query {
    /// The raw maximum response code; values from 0x8000 are floating point.
    pub max_response_code: u16,
    pub reserved: u16,
    pub group: Ipv6Addr,
    /// The four reserved bits before the suppress flag.
    pub reserved_flags: u8,
    pub suppress_router_processing: bool,
    pub robustness: u8,
    /// The raw querier's query interval code.
    pub qqic: u8,
    pub sources: Vec<Ipv6Addr>,
}

impl Mldv2Query {
    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let Some((fixed, rest)) = body.split_first_chunk::<MLDV2_QUERY_LENGTH>() else {
            return Err(truncated(MLDV2_QUERY_LENGTH, body.len()));
        };
        let count = usize::from(u16::from_be_bytes([fixed[22], fixed[23]]));
        let sources = read_sources(rest, count)?;
        Ok(Self {
            max_response_code: u16::from_be_bytes([fixed[0], fixed[1]]),
            reserved: u16::from_be_bytes([fixed[2], fixed[3]]),
            group: address(&fixed[4..20]),
            reserved_flags: fixed[20] >> 4,
            suppress_router_processing: fixed[20] & SUPPRESS_FLAG != 0,
            robustness: fixed[20] & ROBUSTNESS_MASK,
            qqic: fixed[21],
            sources: sources.0,
        })
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        if self.reserved_flags > QUERY_RESERVED_MAX {
            return Err(field_range("query reserved", self.reserved_flags));
        }
        if self.robustness > ROBUSTNESS_MASK {
            return Err(field_range("robustness", self.robustness));
        }
        let count = checked_count("source", self.sources.len(), MAX_SOURCES)?;
        let flags = self.reserved_flags << 4
            | if self.suppress_router_processing {
                SUPPRESS_FLAG
            } else {
                0
            }
            | self.robustness;
        let mut body = Vec::with_capacity(MLDV2_QUERY_LENGTH + self.sources.len() * ADDRESS_LENGTH);
        body.extend_from_slice(&self.max_response_code.to_be_bytes());
        body.extend_from_slice(&self.reserved.to_be_bytes());
        body.extend_from_slice(&self.group.octets());
        body.extend_from_slice(&[flags, self.qqic]);
        body.extend_from_slice(&count.to_be_bytes());
        push_sources(&mut body, &self.sources);
        Ok(Bytes::from(body))
    }

    pub fn to_icmpv6(&self) -> Result<Icmpv6, Error> {
        Ok(icmpv6(QUERY, self.encode()?))
    }
}

/// One group record of an MLDv2 report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MulticastAddressRecord {
    /// The raw record type: 1 to 6 are defined, others stay as read.
    pub record_type: u8,
    pub group: Ipv6Addr,
    pub sources: Vec<Ipv6Addr>,
    pub aux_data: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mldv2Report {
    pub reserved: u16,
    pub records: Vec<MulticastAddressRecord>,
}

impl Mldv2Report {
    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let Some((fixed, mut rest)) = body.split_first_chunk::<MLDV2_REPORT_LENGTH>() else {
            return Err(truncated(MLDV2_REPORT_LENGTH, body.len()));
        };
        let count = usize::from(u16::from_be_bytes([fixed[2], fixed[3]]));
        if count > MAX_RECORDS {
            return Err(limit("record", count, MAX_RECORDS));
        }
        // each record needs at least its fixed header, so this bounds the
        // allocation by the bytes actually present
        let minimum = count.saturating_mul(RECORD_LENGTH);
        if rest.len() < minimum {
            return Err(truncated(
                MLDV2_REPORT_LENGTH.saturating_add(minimum),
                body.len(),
            ));
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let Some((header, after)) = rest.split_first_chunk::<RECORD_LENGTH>() else {
                return Err(truncated(RECORD_LENGTH, rest.len()));
            };
            let aux_length = usize::from(header[1]) * AUX_UNIT;
            let sources = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let (sources, after) = read_sources_prefix(after, sources)?;
            let Some((aux_data, after)) = after.split_at_checked(aux_length) else {
                return Err(truncated(aux_length, after.len()));
            };
            records.push(MulticastAddressRecord {
                record_type: header[0],
                group: address(&header[4..]),
                sources,
                aux_data: Bytes::copy_from_slice(aux_data),
            });
            rest = after;
        }
        no_trailing(rest, 0)?;
        Ok(Self {
            reserved: u16::from_be_bytes([fixed[0], fixed[1]]),
            records,
        })
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        let count = checked_count("record", self.records.len(), MAX_RECORDS)?;
        let mut body = Vec::with_capacity(MLDV2_REPORT_LENGTH);
        body.extend_from_slice(&self.reserved.to_be_bytes());
        body.extend_from_slice(&count.to_be_bytes());
        for record in &self.records {
            let sources = checked_count("source", record.sources.len(), MAX_SOURCES)?;
            let aux_words = u8::try_from(record.aux_data.len() / AUX_UNIT)
                .ok()
                .filter(|_| record.aux_data.len() % AUX_UNIT == 0)
                .ok_or(Error::AuxiliaryLength {
                    length: record.aux_data.len(),
                })?;
            body.extend_from_slice(&[record.record_type, aux_words]);
            body.extend_from_slice(&sources.to_be_bytes());
            body.extend_from_slice(&record.group.octets());
            push_sources(&mut body, &record.sources);
            body.extend_from_slice(&record.aux_data);
        }
        Ok(Bytes::from(body))
    }

    pub fn to_icmpv6(&self) -> Result<Icmpv6, Error> {
        Ok(icmpv6(REPORT_V2, self.encode()?))
    }
}

fn icmpv6(icmp_type: u8, body: Bytes) -> Icmpv6 {
    Icmpv6 {
        icmp_type,
        code: 0,
        checksum: WireValue::Auto,
        body,
    }
}

fn truncated(expected: usize, actual: usize) -> Error {
    Error::Truncated { expected, actual }
}

fn limit(what: &'static str, count: usize, limit: usize) -> Error {
    Error::LimitExceeded { what, count, limit }
}

fn field_range(field: &'static str, value: impl Into<u64>) -> Error {
    Error::FieldRange {
        field,
        value: value.into(),
    }
}

fn no_trailing(body: &[u8], consumed: usize) -> Result<(), Error> {
    match body.len().checked_sub(consumed) {
        Some(0) | None => Ok(()),
        Some(length) => Err(Error::TrailingData { length }),
    }
}

/// A list length as the 16-bit wire count, refused above `maximum`.
fn checked_count(what: &'static str, count: usize, maximum: usize) -> Result<u16, Error> {
    if count > maximum {
        return Err(limit(what, count, maximum));
    }
    u16::try_from(count).map_err(|_| limit(what, count, maximum))
}

fn address(bytes: &[u8]) -> Ipv6Addr {
    let mut octets = [0; ADDRESS_LENGTH];
    octets.copy_from_slice(&bytes[..ADDRESS_LENGTH]);
    Ipv6Addr::from(octets)
}

fn push_sources(body: &mut Vec<u8>, sources: &[Ipv6Addr]) {
    for source in sources {
        body.extend_from_slice(&source.octets());
    }
}

/// Reads `count` sources that must fill `rest` exactly.
fn read_sources(rest: &[u8], count: usize) -> Result<(Vec<Ipv6Addr>, &[u8]), Error> {
    let (sources, rest) = read_sources_prefix(rest, count)?;
    no_trailing(rest, 0)?;
    Ok((sources, rest))
}

/// Reads `count` sources from the front of `rest` and returns the remainder.
fn read_sources_prefix(rest: &[u8], count: usize) -> Result<(Vec<Ipv6Addr>, &[u8]), Error> {
    if count > MAX_SOURCES {
        return Err(limit("source", count, MAX_SOURCES));
    }
    let length = count.saturating_mul(ADDRESS_LENGTH);
    let Some((bytes, rest)) = rest.split_at_checked(length) else {
        return Err(truncated(length, rest.len()));
    };
    let sources = bytes
        .as_chunks::<ADDRESS_LENGTH>()
        .0
        .iter()
        .map(|chunk| address(chunk))
        .collect::<Vec<_>>();
    Ok((sources, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(text: &str) -> Ipv6Addr {
        text.parse().expect("address")
    }

    fn report_bytes() -> Vec<u8> {
        let mut body = vec![0, 0, 0, 2];
        // include mode with three sources
        body.extend_from_slice(&[1, 0, 0, 3]);
        body.extend_from_slice(&group("ff3e::1234").octets());
        for source in ["2001:db8::1", "2001:db8::2", "2001:db8::3"] {
            body.extend_from_slice(&group(source).octets());
        }
        // change to exclude with eight bytes of auxiliary data
        body.extend_from_slice(&[4, 2, 0, 0]);
        body.extend_from_slice(&group("ff02::fb").octets());
        body.extend_from_slice(&[9; 8]);
        body
    }

    #[test]
    fn truncated_and_trailing_data_are_refused() {
        let body = report_bytes();
        // the second record's auxiliary data is cut short
        assert_eq!(
            Mldv2Report::decode(&body[..body.len() - 1]),
            Err(Error::Truncated {
                expected: 8,
                actual: 7
            })
        );
        // the first record's source list is cut short
        assert!(matches!(
            Mldv2Report::decode(&body[..4 + 20 + 40]),
            Err(Error::Truncated { .. })
        ));
        let mut trailing = body;
        trailing.push(0);
        assert_eq!(
            Mldv2Report::decode(&trailing),
            Err(Error::TrailingData { length: 1 })
        );
        assert_eq!(
            Mldv1::decode(Mldv1Kind::Done, &[0; 19]),
            Err(Error::Truncated {
                expected: 20,
                actual: 19
            })
        );
        let icmp = Icmpv6 {
            icmp_type: QUERY,
            code: 0,
            checksum: WireValue::Auto,
            body: Bytes::from_static(&[0; 22]),
        };
        assert_eq!(
            Message::from_icmpv6(&icmp),
            Err(Error::Truncated {
                expected: 24,
                actual: 22
            })
        );
    }

    #[test]
    fn unencodable_values_and_foreign_messages_are_refused() {
        let record = |aux: &'static [u8], sources: usize| MulticastAddressRecord {
            record_type: 1,
            group: group("ff02::1"),
            sources: vec![group("2001:db8::1"); sources],
            aux_data: Bytes::from_static(aux),
        };
        let report = |records| Mldv2Report {
            reserved: 0,
            records,
        };
        assert_eq!(
            report(vec![record(&[0; 3], 0)]).encode(),
            Err(Error::AuxiliaryLength { length: 3 })
        );
        assert_eq!(
            report(vec![record(&[], MAX_SOURCES + 1)]).encode(),
            Err(Error::LimitExceeded {
                what: "source",
                count: MAX_SOURCES + 1,
                limit: MAX_SOURCES
            })
        );
        assert_eq!(
            report(vec![record(&[], 0); MAX_RECORDS + 1]).encode(),
            Err(Error::LimitExceeded {
                what: "record",
                count: MAX_RECORDS + 1,
                limit: MAX_RECORDS
            })
        );
        let mut query = Mldv2Query::decode(&[0; 24]).expect("empty query decodes");
        query.robustness = 8;
        assert_eq!(
            query.encode(),
            Err(Error::FieldRange {
                field: "robustness",
                value: 8
            })
        );

        let mut icmp = report(Vec::new()).to_icmpv6().expect("icmpv6");
        icmp.code = 1;
        assert_eq!(Message::from_icmpv6(&icmp), Err(Error::Code { code: 1 }));
        icmp.code = 0;
        icmp.icmp_type = 128;
        let error = Message::from_icmpv6(&icmp).expect_err("echo is not MLD");
        assert_eq!(error, Error::UnsupportedType { icmp_type: 128 });
        assert_eq!(
            crate::error::Classified::classification(&error).code,
            "packet.codec"
        );
    }
}
