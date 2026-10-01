// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IGMPv3 (RFC 3376) membership query and report messages, read from and
//! written to the body of the generic [`Igmp`] layer.
//!
//! Counts read from the wire are checked against the bytes present and
//! against [`MAX_RECORDS`] and [`MAX_SOURCES`] before anything is allocated.
//! ```
//! use packetcraftr_core::protocol::network::igmpv3::{GroupRecord, Report};
//!
//! let report = Report {
//!     reserved: 0,
//!     reserved2: 0,
//!     records: vec![GroupRecord {
//!         record_type: 1,
//!         group: "232.1.1.1".parse()?,
//!         sources: vec!["192.0.2.10".parse()?],
//!         aux_data: Default::default(),
//!     }],
//! };
//! let igmp = report.to_igmp()?;
//! assert_eq!(igmp.igmp_type, 0x22);
//! assert_eq!(Report::from_igmp(&igmp)?, report);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::net::Ipv4Addr;

use bytes::Bytes;

use crate::field::WireValue;

use super::Igmp;

pub const MEMBERSHIP_QUERY: u8 = 0x11;
pub const V3_MEMBERSHIP_REPORT: u8 = 0x22;

/// Most group records one report may carry.
pub const MAX_RECORDS: usize = 1024;
/// Most sources one query or group record may carry.
pub const MAX_SOURCES: usize = 1024;

const ADDRESS_LENGTH: usize = 4;
/// The query body before its sources: group, flags, QQIC and source count.
const QUERY_LENGTH: usize = 8;
/// The report body before its records: reserved and record count.
const REPORT_LENGTH: usize = 4;
const RECORD_LENGTH: usize = 8;
/// Auxiliary data is sized in 32-bit words.
const AUX_UNIT: usize = 4;
const SUPPRESS_FLAG: u8 = 0x08;
const ROBUSTNESS_MASK: u8 = 0x07;
const QUERY_RESERVED_MAX: u8 = 0x0f;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("IGMPv3 message body is {actual} bytes; expected at least {expected}")]
    Truncated { expected: usize, actual: usize },
    #[error("{length} bytes follow the last IGMPv3 entry")]
    TrailingData { length: usize },
    #[error("IGMP type {igmp_type:#04x} is not the IGMPv3 message this helper reads")]
    UnsupportedType { igmp_type: u8 },
    #[error("IGMPv3 {what} count {count} exceeds the limit of {limit}")]
    LimitExceeded {
        what: &'static str,
        count: usize,
        limit: usize,
    },
    #[error("IGMPv3 {field} value {value:#x} does not fit its bit width")]
    FieldRange { field: &'static str, value: u64 },
    #[error(
        "IGMPv3 auxiliary data of {length} bytes is not a whole number of 32-bit words up to 255"
    )]
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

/// An IGMPv3 membership query. The generic layer's `code` is the maximum
/// response code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// The raw maximum response code; values from 128 are floating point.
    pub max_response_code: u8,
    pub group: Ipv4Addr,
    /// The four reserved bits before the suppress flag.
    pub reserved: u8,
    pub suppress_router_processing: bool,
    pub robustness: u8,
    /// The raw querier's query interval code.
    pub qqic: u8,
    pub sources: Vec<Ipv4Addr>,
}

impl Query {
    pub fn from_igmp(igmp: &Igmp) -> Result<Self, Error> {
        if igmp.igmp_type != MEMBERSHIP_QUERY {
            return Err(Error::UnsupportedType {
                igmp_type: igmp.igmp_type,
            });
        }
        let Some((fixed, rest)) = igmp.body.split_first_chunk::<QUERY_LENGTH>() else {
            return Err(truncated(QUERY_LENGTH, igmp.body.len()));
        };
        let count = usize::from(u16::from_be_bytes([fixed[6], fixed[7]]));
        let (sources, rest) = read_sources(rest, count)?;
        no_trailing(rest)?;
        Ok(Self {
            max_response_code: igmp.code,
            group: address(&fixed[..4]),
            reserved: fixed[4] >> 4,
            suppress_router_processing: fixed[4] & SUPPRESS_FLAG != 0,
            robustness: fixed[4] & ROBUSTNESS_MASK,
            qqic: fixed[5],
            sources,
        })
    }

    pub fn to_igmp(&self) -> Result<Igmp, Error> {
        if self.reserved > QUERY_RESERVED_MAX {
            return Err(field_range("query reserved", self.reserved));
        }
        if self.robustness > ROBUSTNESS_MASK {
            return Err(field_range("robustness", self.robustness));
        }
        let count = checked_count("source", self.sources.len(), MAX_SOURCES)?;
        let flags = self.reserved << 4
            | if self.suppress_router_processing {
                SUPPRESS_FLAG
            } else {
                0
            }
            | self.robustness;
        let mut body = Vec::with_capacity(QUERY_LENGTH + self.sources.len() * ADDRESS_LENGTH);
        body.extend_from_slice(&self.group.octets());
        body.extend_from_slice(&[flags, self.qqic]);
        body.extend_from_slice(&count.to_be_bytes());
        push_sources(&mut body, &self.sources);
        Ok(igmp(MEMBERSHIP_QUERY, self.max_response_code, body))
    }
}

/// One group record of an IGMPv3 report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRecord {
    /// The raw record type: 1 to 6 are defined, others stay as read.
    pub record_type: u8,
    pub group: Ipv4Addr,
    pub sources: Vec<Ipv4Addr>,
    pub aux_data: Bytes,
}

/// An IGMPv3 membership report. The generic layer's `code` is the reserved
/// octet that precedes the checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The reserved octet that takes the generic layer's `code` place.
    pub reserved: u8,
    /// The reserved word before the record count.
    pub reserved2: u16,
    pub records: Vec<GroupRecord>,
}

impl Report {
    pub fn from_igmp(igmp: &Igmp) -> Result<Self, Error> {
        if igmp.igmp_type != V3_MEMBERSHIP_REPORT {
            return Err(Error::UnsupportedType {
                igmp_type: igmp.igmp_type,
            });
        }
        let Some((fixed, mut rest)) = igmp.body.split_first_chunk::<REPORT_LENGTH>() else {
            return Err(truncated(REPORT_LENGTH, igmp.body.len()));
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
                REPORT_LENGTH.saturating_add(minimum),
                igmp.body.len(),
            ));
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let Some((header, after)) = rest.split_first_chunk::<RECORD_LENGTH>() else {
                return Err(truncated(RECORD_LENGTH, rest.len()));
            };
            let aux_length = usize::from(header[1]) * AUX_UNIT;
            let sources = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let (sources, after) = read_sources(after, sources)?;
            let Some((aux_data, after)) = after.split_at_checked(aux_length) else {
                return Err(truncated(aux_length, after.len()));
            };
            records.push(GroupRecord {
                record_type: header[0],
                group: address(&header[4..]),
                sources,
                aux_data: Bytes::copy_from_slice(aux_data),
            });
            rest = after;
        }
        no_trailing(rest)?;
        Ok(Self {
            reserved: igmp.code,
            reserved2: u16::from_be_bytes([fixed[0], fixed[1]]),
            records,
        })
    }

    pub fn to_igmp(&self) -> Result<Igmp, Error> {
        let count = checked_count("record", self.records.len(), MAX_RECORDS)?;
        let mut body = Vec::with_capacity(REPORT_LENGTH);
        body.extend_from_slice(&self.reserved2.to_be_bytes());
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
        Ok(igmp(V3_MEMBERSHIP_REPORT, self.reserved, body))
    }
}

fn igmp(igmp_type: u8, code: u8, body: Vec<u8>) -> Igmp {
    Igmp {
        igmp_type,
        code,
        checksum: WireValue::Auto,
        body: Bytes::from(body),
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

fn no_trailing(rest: &[u8]) -> Result<(), Error> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(Error::TrailingData { length: rest.len() })
    }
}

/// A list length as the 16-bit wire count, refused above `maximum`.
fn checked_count(what: &'static str, count: usize, maximum: usize) -> Result<u16, Error> {
    if count > maximum {
        return Err(limit(what, count, maximum));
    }
    u16::try_from(count).map_err(|_| limit(what, count, maximum))
}

fn address(bytes: &[u8]) -> Ipv4Addr {
    let mut octets = [0; ADDRESS_LENGTH];
    octets.copy_from_slice(&bytes[..ADDRESS_LENGTH]);
    Ipv4Addr::from(octets)
}

fn push_sources(body: &mut Vec<u8>, sources: &[Ipv4Addr]) {
    for source in sources {
        body.extend_from_slice(&source.octets());
    }
}

/// Reads `count` sources from the front of `rest` and returns the remainder.
fn read_sources(rest: &[u8], count: usize) -> Result<(Vec<Ipv4Addr>, &[u8]), Error> {
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

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("address")
    }

    fn query() -> Query {
        Query {
            max_response_code: 100,
            group: ip("232.1.1.1"),
            reserved: 0b0101,
            suppress_router_processing: true,
            robustness: 2,
            qqic: 125,
            sources: vec![ip("192.0.2.1"), ip("192.0.2.2")],
        }
    }

    #[test]
    fn query_with_sources_converts_to_the_same_body_bytes() {
        let igmp = query().to_igmp().expect("query encodes");
        assert_eq!((igmp.igmp_type, igmp.code), (0x11, 100));
        assert_eq!(igmp.checksum, WireValue::Auto);
        let mut expected = vec![232, 1, 1, 1, 0b0101_1010, 125, 0, 2];
        expected.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        assert_eq!(igmp.body.as_ref(), expected);
        let decoded = Query::from_igmp(&igmp).expect("query decodes");
        assert_eq!(decoded, query());
        assert_eq!(decoded.to_igmp().expect("re-encodes"), igmp);
    }

    #[test]
    fn report_records_round_trip_with_modes_sources_and_auxiliary_data() {
        let report = Report {
            reserved: 0x07,
            reserved2: 0x0102,
            records: vec![
                GroupRecord {
                    record_type: 1,
                    group: ip("232.1.1.1"),
                    sources: vec![ip("192.0.2.9")],
                    aux_data: Bytes::new(),
                },
                GroupRecord {
                    record_type: 6,
                    group: ip("239.0.0.5"),
                    sources: Vec::new(),
                    aux_data: Bytes::from_static(&[1, 2, 3, 4]),
                },
            ],
        };
        let igmp = report.to_igmp().expect("report encodes");
        assert_eq!((igmp.igmp_type, igmp.code), (0x22, 0x07));
        assert_eq!(&igmp.body[..4], &[1, 2, 0, 2]);
        assert_eq!(Report::from_igmp(&igmp), Ok(report));
    }

    #[test]
    fn counts_are_checked_against_the_bytes_and_the_limits() {
        let report = |body: &'static [u8]| Igmp {
            igmp_type: V3_MEMBERSHIP_REPORT,
            body: Bytes::from_static(body),
            ..Igmp::default()
        };
        assert_eq!(
            Report::from_igmp(&report(&[0, 0, 0xff, 0xff])),
            Err(Error::LimitExceeded {
                what: "record",
                count: 65_535,
                limit: MAX_RECORDS
            })
        );
        assert_eq!(
            Report::from_igmp(&report(&[0, 0, 0x03, 0xe8, 1, 0])),
            Err(Error::Truncated {
                expected: 4 + 1000 * 8,
                actual: 6
            })
        );
        assert_eq!(
            Report::from_igmp(&report(&[0, 0, 0, 1, 1, 0, 0x04, 0x01, 0, 0, 0, 0])),
            Err(Error::LimitExceeded {
                what: "source",
                count: 1025,
                limit: MAX_SOURCES
            })
        );
        let mut query = query().to_igmp().expect("query encodes");
        let mut body = query.body.to_vec();
        body[6] = 0xff;
        body[7] = 0xff;
        query.body = Bytes::from(body);
        assert!(matches!(
            Query::from_igmp(&query),
            Err(Error::LimitExceeded { what: "source", .. })
        ));
    }

    #[test]
    fn truncated_and_trailing_data_are_refused() {
        let mut query = query().to_igmp().expect("query encodes");
        let body = query.body.clone();
        query.body = body.slice(..body.len() - 1);
        assert_eq!(
            Query::from_igmp(&query),
            Err(Error::Truncated {
                expected: 8,
                actual: 7
            })
        );
        query.body = body.slice(..6);
        assert_eq!(
            Query::from_igmp(&query),
            Err(Error::Truncated {
                expected: 8,
                actual: 6
            })
        );
        let mut padded = body.to_vec();
        padded.push(0);
        query.body = Bytes::from(padded);
        assert_eq!(
            Query::from_igmp(&query),
            Err(Error::TrailingData { length: 1 })
        );

        let mut report = Report {
            reserved: 0,
            reserved2: 0,
            records: vec![GroupRecord {
                record_type: 2,
                group: ip("232.1.1.1"),
                sources: vec![ip("192.0.2.9")],
                aux_data: Bytes::from_static(&[0; 8]),
            }],
        }
        .to_igmp()
        .expect("report encodes");
        let body = report.body.clone();
        for length in [body.len() - 1, 4 + 8 + 2] {
            report.body = body.slice(..length);
            assert!(
                matches!(Report::from_igmp(&report), Err(Error::Truncated { .. })),
                "{length}"
            );
        }
    }

    #[test]
    fn unencodable_values_and_other_igmp_messages_are_refused() {
        let mut bad = query();
        bad.robustness = 8;
        assert_eq!(
            bad.to_igmp(),
            Err(Error::FieldRange {
                field: "robustness",
                value: 8
            })
        );
        bad = query();
        bad.reserved = 16;
        assert!(matches!(
            bad.to_igmp(),
            Err(Error::FieldRange {
                field: "query reserved",
                ..
            })
        ));
        bad = query();
        bad.sources = vec![ip("192.0.2.1"); MAX_SOURCES + 1];
        assert!(matches!(
            bad.to_igmp(),
            Err(Error::LimitExceeded { what: "source", .. })
        ));
        let record = GroupRecord {
            record_type: 1,
            group: ip("232.1.1.1"),
            sources: Vec::new(),
            aux_data: Bytes::from_static(&[0; 5]),
        };
        let report = Report {
            reserved: 0,
            reserved2: 0,
            records: vec![record],
        };
        assert_eq!(report.to_igmp(), Err(Error::AuxiliaryLength { length: 5 }));

        let v2_report = Igmp {
            igmp_type: 0x16,
            ..Igmp::default()
        };
        let error = Report::from_igmp(&v2_report).expect_err("v2 report");
        assert_eq!(error, Error::UnsupportedType { igmp_type: 0x16 });
        assert_eq!(
            crate::error::Classified::classification(&error).code,
            "packet.codec"
        );
        // an IGMPv2 query has no room for the v3 fields
        assert_eq!(
            Query::from_igmp(&Igmp::default()),
            Err(Error::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }
}
