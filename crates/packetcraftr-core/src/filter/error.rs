// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use thiserror::Error;

use crate::error::{Classification, Classified, Kind};

#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Decode(Arc<crate::decode::Error>),
    #[error(
        "display filter reads a conversation index, which frame-at-a-time selection does not assign"
    )]
    StreamIndexUnavailable,
    #[error(
        "display filter requires frame.time_epoch or frame.time_nsec, but the frame has no timestamp"
    )]
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
        "unquoted word {literal} at byte {offset} for field {path} is neither separated bytes nor quoted text"
    )]
    UnquotedByteWord {
        offset: usize,
        path: String,
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
    #[error(
        "field {path} at byte {offset} is compared to range {literal}, \
         which only `==`, `!=`, and `in` can test"
    )]
    OrderedRangeComparison {
        offset: usize,
        path: String,
        literal: String,
    },
    #[error("range {literal} for field {path} at byte {offset} is invalid: {reason}")]
    InvalidRange {
        offset: usize,
        path: String,
        literal: String,
        reason: &'static str,
    },
    #[error("field {path} at byte {offset} holds {kind}, which cannot take a bitwise `&` mask")]
    MaskedField {
        offset: usize,
        path: String,
        kind: &'static str,
    },
    #[error(
        "bitwise mask on field {path} at byte {offset} needs an unsigned number, found {found}"
    )]
    MaskOperand {
        offset: usize,
        path: String,
        found: String,
    },
    #[error("protocol {protocol} has no reflective schema, so {path} cannot be resolved")]
    UnresolvableProtocol {
        path: String,
        protocol: crate::layer::Id,
    },
    #[error("invalid projection field")]
    ProjectionField {
        #[source]
        source: Box<Self>,
    },
    #[error("projection exceeds {field}={limit}")]
    ProjectionLimit { field: &'static str, limit: usize },
}

impl From<crate::decode::Error> for Error {
    fn from(source: crate::decode::Error) -> Self {
        Self::Decode(Arc::new(source))
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Decode(source) => source.classification(),
            Self::StreamIndexUnavailable => Classification::new(
                "cli.filter_unsupported_field",
                Kind::Usage,
                Some("select by conversation with an analysis pass, or filter on header fields"),
            ),
            Self::ProjectionField { .. } => Classification::new(
                "cli.projection_field",
                Kind::Usage,
                Some("select registered field paths"),
            ),
            Self::ProjectionLimit { .. } => Classification::new(
                "policy.projection_limit",
                Kind::Policy,
                Some("select fewer or smaller fields within the finite projection budget"),
            ),
            Self::TimestampUnavailable => Classification::new(
                "packet.timestamp_unavailable",
                Kind::Packet,
                Some(
                    "remove frame.time_epoch and frame.time_nsec from the filter or use timestamped packet blocks",
                ),
            ),
            Self::UnknownField { .. } | Self::UnresolvableProtocol { .. } => cli_filter(
                "run `packetcraftr protocols <PROTOCOL>` to list the fields a protocol exposes",
            ),
            Self::IncompatibleLiteral { .. }
            | Self::OrderedPrefixComparison { .. }
            | Self::OrderedRangeComparison { .. } => {
                cli_filter("compare the field against a value of its own type")
            }
            Self::InvalidRange { .. } => cli_filter(
                "write a range as LOW..HIGH with two unsigned numbers or two addresses of one family, LOW not above HIGH",
            ),
            Self::MaskedField { .. } | Self::MaskOperand { .. } => cli_filter(
                "mask only unsigned number fields, as in `tcp.flags & 0x12 == 0x12`, with unsigned masks and values",
            ),
            Self::UnquotedByteWord { .. } => cli_filter(
                "write bytes as two-digit groups with separators such as c0:00; on byte fields, quote the word to match it as ASCII text",
            ),
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
    use crate::filter::{Filter, Limits};
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
    fn byte_spelling_advice_is_limited_to_byte_word_errors() {
        let registry = builtin::registry();
        let remediation = |source: &str| {
            Filter::compile(source, &registry, Limits::default())
                .expect_err("fixture filter must fail")
                .classification()
                .remediation
        };

        for source in [
            "tcp.source_port == \"abc\"",
            "tcp.source_port contains \"x\"",
            "ipv4.source == 7",
            "ipv4.source == 300.0.0.1",
        ] {
            assert_eq!(
                remediation(source),
                Some("compare the field against a value of its own type"),
                "{source}"
            );
        }
        for source in ["raw.bytes contains deadbeef", "raw.bytes contains 47:45:5"] {
            let advice = remediation(source).expect("byte word errors have remediation");
            assert!(advice.contains("c0:00"), "{source}: {advice}");
            assert!(advice.contains("quote"), "{source}: {advice}");
        }
    }

    #[test]
    fn filter_error_remediation_is_specific() {
        let registry = builtin::registry();
        let cases = [
            ("ipv4.missing == 1", "list the fields a protocol exposes"),
            ("udp.destination_port == 192.0.2.1", "value of its own type"),
            ("raw.bytes contains deadbeef", "two-digit groups"),
            ("raw.bytes contains 47:45:5", "two-digit groups"),
            ("frame.len[0] == 1", "slice only fields that hold bytes"),
            ("(ethernet", "check the filter syntax"),
            ("tcp.port in 9..1", "LOW..HIGH"),
            ("tcp.port > 1..9", "value of its own type"),
            ("ip.src & 1", "mask only unsigned number fields"),
            ("tcp.flags & abc", "mask only unsigned number fields"),
        ];

        for (source, expected_remediation) in cases {
            let error = Filter::compile(source, &registry, Limits::default())
                .expect_err("fixture filter must fail");
            assert_eq!(error.classification().code, "cli.filter", "{source}");
            assert_eq!(error.classification().kind, Kind::Usage, "{source}");
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
