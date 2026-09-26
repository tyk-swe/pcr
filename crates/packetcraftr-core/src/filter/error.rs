// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::error::{Classification, Classified, Kind};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("display filter requires frame.time_epoch, but the frame has no timestamp")]
    TimestampUnavailable,
    #[error("display filter is empty")]
    Empty,
    #[error("display filter has {actual} bytes, exceeding limit {limit}")]
    SizeLimit { actual: usize, limit: usize },
    #[error("display filter nesting exceeds configured limit {limit}")]
    NestingLimit { limit: usize },
    #[error("display filter nesting limit {value} exceeds stable maximum {maximum}")]
    InvalidNestingLimit { value: usize, maximum: usize },
    #[error("display filter term limit {value} exceeds stable maximum {maximum}")]
    InvalidTermLimit { value: usize, maximum: usize },
    #[error("display filter has more than {limit} terms")]
    TermLimit { limit: usize },
    #[error("display filter set has more than {limit} members")]
    SetMemberLimit { limit: usize },
    #[error("display filter set-member limit {value} exceeds stable maximum {maximum}")]
    InvalidSetMemberLimit { value: usize, maximum: usize },
    #[error("display filter syntax error at byte {offset}: {message}")]
    Syntax { offset: usize, message: String },
    #[error("unknown display filter field {path} at byte {offset}")]
    UnknownField { offset: usize, path: String },
    #[error("field {path} at byte {offset} is not a byte sequence, so it cannot be sliced")]
    UnsliceableField { offset: usize, path: String },
    #[error("field {path} at byte {offset} holds {kind}, which cannot be compared to {literal}")]
    IncompatibleLiteral {
        offset: usize,
        path: String,
        kind: &'static str,
        literal: String,
    },
    #[error(
        "field {path} at byte {offset} is compared to prefix {literal}, \
         which only `==` and `!=` can test"
    )]
    OrderedPrefixComparison {
        offset: usize,
        path: String,
        literal: String,
    },
    #[error("protocol {protocol} has no reflective schema, so {path} cannot be resolved")]
    UnresolvableProtocol {
        path: String,
        protocol: crate::layer::Id,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::TimestampUnavailable => Classification::new(
                "packet.timestamp_unavailable",
                Kind::Packet,
                Some("remove frame.time_epoch from the filter or use timestamped packet blocks"),
            ),
            Self::UnknownField { .. } | Self::UnresolvableProtocol { .. } => cli_filter(
                "run `packetcraftr protocols <PROTOCOL>` to list the fields a protocol exposes",
            ),
            Self::IncompatibleLiteral { .. } | Self::OrderedPrefixComparison { .. } => {
                cli_filter("compare the field against a value of its own type")
            }
            Self::UnsliceableField { .. } => {
                cli_filter("slice only fields that hold bytes, such as an address or a byte string")
            }
            Self::SizeLimit { .. }
            | Self::NestingLimit { .. }
            | Self::TermLimit { .. }
            | Self::SetMemberLimit { .. }
            | Self::InvalidNestingLimit { .. }
            | Self::InvalidTermLimit { .. }
            | Self::InvalidSetMemberLimit { .. } => {
                cli_filter("simplify the filter to fit the stable bounds")
            }
            Self::Empty | Self::Syntax { .. } => {
                cli_filter("check the filter syntax; see `packetcraftr read --help` for examples")
            }
        }
    }
}

fn cli_filter(remediation: &'static str) -> Classification {
    Classification::new("cli.filter", Kind::Usage, Some(remediation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{Filter, Options};
    use crate::protocol::builtin;

    #[test]
    fn timestamp_unavailable_is_a_packet_failure() {
        let classification = Error::TimestampUnavailable.classification();
        assert_eq!(classification.code, "packet.timestamp_unavailable");
        assert_eq!(classification.kind, Kind::Packet);
        assert!(
            classification
                .remediation
                .is_some_and(|value| value.contains("frame.time_epoch"))
        );
    }

    #[test]
    fn empty_and_syntax_errors_are_filter_failures() {
        for error in [
            Error::Empty,
            Error::Syntax {
                offset: 0,
                message: "fixture".to_owned(),
            },
        ] {
            let classification = error.classification();
            assert_eq!(classification.code, "cli.filter");
            assert_eq!(classification.kind, Kind::Usage);
            assert!(
                classification
                    .remediation
                    .is_some_and(|value| value.contains("check the filter syntax"))
            );
        }
    }

    #[test]
    fn filter_error_remediation_is_specific() {
        let registry = builtin::registry();
        let cases = [
            ("ipv4.missing == 1", "list the fields a protocol exposes"),
            ("udp.destination_port == 192.0.2.1", "value of its own type"),
            ("frame.len[0] == 1", "slice only fields that hold bytes"),
            ("(ethernet", "check the filter syntax"),
        ];

        for (source, expected_remediation) in cases {
            let error = Filter::compile(source, &registry, Options::default())
                .expect_err("fixture filter must fail");
            assert_eq!(error.classification().code, "cli.filter", "{source}");
            assert!(
                error
                    .classification()
                    .remediation
                    .is_some_and(|value| value.contains(expected_remediation)),
                "{source}: {:?}",
                error.classification().remediation
            );
        }
    }
}
