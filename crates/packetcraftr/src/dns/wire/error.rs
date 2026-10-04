// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use packetcraftr_core::error::{Classification, Classified, Kind};

#[derive(Clone, Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Encode(#[from] packetcraftr_core::codec::Error),
    #[error(transparent)]
    Decode(#[from] packetcraftr_core::protocol::application::dns::Error),
    #[error("expected a DNS type alias, 1–5 decimal digits, or TYPE followed by 1–5 digits")]
    QueryTypeSyntax,
    #[error("DNS query type must be within 0..=65535")]
    QueryTypeRange(#[source] std::num::ParseIntError),

    #[error("DNS name is invalid: {message}")]
    InvalidName { message: String },
    #[error("DNS message is a query, not a response")]
    NotResponse,
    #[error("DNS opcode {opcode} is unsupported for a standard query response")]
    UnsupportedOpcode { opcode: u8 },
    #[error("DNS reserved header bits are non-zero")]
    ReservedHeaderBits,
    #[error("DNS response transaction ID {actual} does not match {expected}")]
    TransactionIdMismatch { expected: u16, actual: u16 },
    #[error("DNS response contains {actual} questions; expected exactly one")]
    QuestionCount { actual: u16 },
    #[error("DNS response question name {actual} does not match {expected}")]
    QuestionNameMismatch { expected: String, actual: String },
    #[error("DNS response question type {actual} does not match {expected}")]
    QuestionTypeMismatch { expected: u16, actual: u16 },
    #[error("DNS response question class {actual} is not IN")]
    QuestionClassMismatch { actual: u16 },
    #[error("DNS response contains more than one EDNS OPT pseudo-record")]
    DuplicateEdns,
    #[error("DNS EDNS version {version} is unsupported")]
    UnsupportedEdnsVersion { version: u8 },
    #[error("DNS EDNS metadata is invalid: {message}")]
    InvalidEdns { message: String },
    #[error("DNS query EDNS UDP payload size {value} must be within 512..=65535")]
    InvalidEdnsPayloadSize { value: u16 },
    #[error(
        "DNS name exceeds the {}-byte wire limit",
        packetcraftr_core::protocol::application::dns::MAX_NAME_LEN
    )]
    NameTooLong,
    #[error("DNS-over-TCP frame declares a zero-length DNS message")]
    TcpFrameZeroLength,
    #[error("DNS-over-TCP frame length {declared} does not match {actual} payload byte(s)")]
    TcpFrameLength { declared: usize, actual: usize },
    #[error("DNS-over-TCP response is still truncated")]
    TcpResponseTruncated,
}

impl Error {
    pub const fn is_unrelated(&self) -> bool {
        matches!(
            self,
            Self::TransactionIdMismatch { .. }
                | Self::QuestionNameMismatch { .. }
                | Self::QuestionTypeMismatch { .. }
                | Self::QuestionClassMismatch { .. }
        )
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Encode(source) => source.classification(),
            Self::Decode(source) => source.classification(),
            Self::InvalidName { .. }
            | Self::InvalidEdnsPayloadSize { .. }
            | Self::NameTooLong
            | Self::QueryTypeSyntax
            | Self::QueryTypeRange(_) => Classification::new(
                "packet.dns_query",
                Kind::Packet,
                Some(
                    "use a bounded ASCII DNS name, a 16-bit query type, and an EDNS payload size within 512..=65535 when enabled",
                ),
            ),
            _ => Classification::new(
                "packet.dns",
                Kind::Packet,
                Some("inspect the DNS message that breaks a wire rule"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_edns_validation_is_distinct_from_malformed_response_metadata() {
        for value in [0, 511] {
            let error = crate::dns::EdnsRequest {
                udp_payload_size: value,
                dnssec_ok: false,
            }
            .validate()
            .unwrap_err();
            assert_eq!(error, Error::InvalidEdnsPayloadSize { value });
            assert_eq!(error.classification().code, "packet.dns_query");
        }
        assert!(
            crate::dns::EdnsRequest {
                udp_payload_size: 512,
                dnssec_ok: false,
            }
            .validate()
            .is_ok()
        );
        assert_eq!(
            Error::InvalidEdns {
                message: "malformed response OPT".into(),
            }
            .classification()
            .code,
            "packet.dns"
        );
    }
}
