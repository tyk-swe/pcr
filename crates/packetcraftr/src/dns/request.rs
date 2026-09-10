// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_netio::capture::{MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES};

use crate::probe::evidence::{check_limits, duration_violation};
use crate::target::Family;
use crate::target::Target;

use crate::dns::error::Error;
use crate::dns::wire::canonical_query_name;
use crate::dns::{
    DEFAULT_MAX_NAME_POINTERS, DEFAULT_MAX_RECORDS, DEFAULT_MAX_REJECTED_RECORDS,
    DEFAULT_MAX_TXT_BYTES, DEFAULT_MAX_TXT_STRINGS, DEFAULT_MAX_UNDECODED_FRAMES, MAX_ATTEMPTS,
    MAX_DURATION, MAX_MESSAGE_BYTES, MAX_NAME_POINTERS, MAX_RATE, MAX_RECORDS,
};

/// A DNS question's exact 16-bit wire code, including unassigned codes.
///
/// Text accepts the named constants' aliases, decimal codes, or `TYPE<n>`.
/// Numeric syntax contains one to five ASCII digits in `0..=65535`.
/// Serialization uses the numeric code; display uses a lowercase known alias
/// or `TYPE<n>` for other codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct QueryType(u16);

impl QueryType {
    pub const A: Self = Self(1);
    pub const NS: Self = Self(2);
    pub const CNAME: Self = Self(5);
    pub const SOA: Self = Self(6);
    pub const PTR: Self = Self(12);
    pub const MX: Self = Self(15);
    pub const TXT: Self = Self(16);
    pub const AAAA: Self = Self(28);
    pub const SRV: Self = Self(33);
    pub const ANY: Self = Self(255);
    pub const CAA: Self = Self(257);

    const ALIASES: [(Self, &'static str); 11] = [
        (Self::A, "a"),
        (Self::AAAA, "aaaa"),
        (Self::CAA, "caa"),
        (Self::CNAME, "cname"),
        (Self::MX, "mx"),
        (Self::NS, "ns"),
        (Self::PTR, "ptr"),
        (Self::SOA, "soa"),
        (Self::SRV, "srv"),
        (Self::TXT, "txt"),
        (Self::ANY, "any"),
    ];

    /// Preserves any 16-bit code without assigning it record semantics.
    pub const fn new(code: u16) -> Self {
        Self(code)
    }

    pub const fn code(self) -> u16 {
        self.0
    }
}

impl Default for QueryType {
    fn default() -> Self {
        Self::A
    }
}

impl fmt::Display for QueryType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Self::ALIASES
            .iter()
            .find(|(query_type, _)| query_type == self)
        {
            Some((_, alias)) => formatter.write_str(alias),
            None => write!(formatter, "TYPE{}", self.0),
        }
    }
}

/// Invalid bounded DNS query-type text.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum QueryTypeParseError {
    #[error("expected a DNS type alias, 1–5 decimal digits, or TYPE followed by 1–5 digits")]
    Syntax,
    #[error("DNS query type must be within 0..=65535")]
    OutOfRange(#[source] std::num::ParseIntError),
}

impl std::str::FromStr for QueryType {
    type Err = QueryTypeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > 9 {
            return Err(QueryTypeParseError::Syntax);
        }
        for (query_type, alias) in Self::ALIASES {
            if value.eq_ignore_ascii_case(alias) {
                return Ok(query_type);
            }
        }
        let digits = if value
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("type"))
        {
            &value[4..]
        } else {
            value
        };
        if digits.is_empty()
            || digits.len() > 5
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(QueryTypeParseError::Syntax);
        }
        digits
            .parse()
            .map(Self)
            .map_err(QueryTypeParseError::OutOfRange)
    }
}

/// Bounds every decision the DNS message codec makes about hostile input.
///
/// These are separate from the workflow's [`Limits`]: decoding one message has
/// nothing to say about capture-queue frames or an operation deadline, so a
/// caller of [`decode_response`](crate::dns::decode_response) is not asked for
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageLimits {
    pub max_message_bytes: usize,
    pub max_records: usize,
    pub max_name_pointers: usize,
    pub max_txt_strings: usize,
    pub max_txt_bytes: usize,
    pub max_rejected_records: usize,
}

impl Default for MessageLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: MAX_MESSAGE_BYTES,
            max_records: DEFAULT_MAX_RECORDS,
            max_name_pointers: DEFAULT_MAX_NAME_POINTERS,
            max_txt_strings: DEFAULT_MAX_TXT_STRINGS,
            max_txt_bytes: DEFAULT_MAX_TXT_BYTES,
            max_rejected_records: DEFAULT_MAX_REJECTED_RECORDS,
        }
    }
}

impl MessageLimits {
    /// Rejects any bound above the ceiling this crate enforces, and any pair
    /// of bounds that cannot both hold.
    pub fn validate(&self) -> Result<(), Error> {
        check_limits(
            &[
                (
                    "max_message_bytes",
                    self.max_message_bytes,
                    MAX_MESSAGE_BYTES,
                ),
                ("max_records", self.max_records, MAX_RECORDS),
                (
                    "max_name_pointers",
                    self.max_name_pointers,
                    MAX_NAME_POINTERS,
                ),
                ("max_txt_strings", self.max_txt_strings, MAX_RECORDS),
                ("max_txt_bytes", self.max_txt_bytes, MAX_MESSAGE_BYTES),
            ],
            &[(
                "max_rejected_records",
                self.max_rejected_records,
                self.max_records,
                "cannot exceed max_records",
            )],
            |field, value, reason| Error::InvalidLimit {
                field,
                value,
                reason,
            },
        )
    }
}

/// Bounds one DNS workflow operation: the message codec, the exact evidence it
/// retains, and its duration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub message: MessageLimits,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_undecoded: usize,
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            message: MessageLimits::default(),
            max_evidence_frames: MAX_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: MAX_CAPTURE_QUEUE_BYTES,
            max_undecoded: DEFAULT_MAX_UNDECODED_FRAMES,
            max_duration: MAX_DURATION,
        }
    }
}

impl Limits {
    /// Rejects any bound above the ceiling this crate enforces, and any pair
    /// of bounds that cannot both hold.
    pub fn validate(&self) -> Result<(), Error> {
        self.message.validate()?;
        check_limits(
            &[
                (
                    "max_evidence_frames",
                    self.max_evidence_frames,
                    MAX_CAPTURE_QUEUE_FRAMES,
                ),
                (
                    "max_evidence_bytes",
                    self.max_evidence_bytes,
                    MAX_CAPTURE_QUEUE_BYTES,
                ),
            ],
            &[(
                "max_undecoded",
                self.max_undecoded,
                self.max_evidence_frames,
                "cannot exceed max_evidence_frames",
            )],
            |field, value, reason| Error::InvalidLimit {
                field,
                value,
                reason,
            },
        )?;
        if duration_violation(self.max_duration, MAX_DURATION) {
            return Err(Error::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_DURATION,
            });
        }
        Ok(())
    }
}

/// Opt-in EDNS version 0 query settings. No custom options are emitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdnsRequest {
    /// Advertised UDP response capacity, within 512..=65535 bytes.
    /// This does not change capture or message decoding limits.
    pub udp_payload_size: u16,
    /// Request DNSSEC records; this does not perform signature validation.
    pub dnssec_ok: bool,
}

impl EdnsRequest {
    /// Validates the advertised UDP response capacity before query construction.
    pub fn validate(&self) -> Result<(), crate::dns::error::WireError> {
        if self.udp_payload_size < 512 {
            return Err(crate::dns::error::WireError::InvalidEdns {
                message: format!(
                    "request UDP payload size {} must be within 512..=65535",
                    self.udp_payload_size
                ),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub server: Target,
    pub address_family: Family,
    pub server_port: u16,
    pub source_port: u16,
    pub query_name: String,
    pub query_type: QueryType,
    pub transaction_id: u16,
    pub recursion_desired: bool,
    /// Optional EDNS v0 settings; absent settings preserve the plain DNS query.
    #[serde(default)]
    pub edns: Option<EdnsRequest>,
    /// Whether a validated truncated UDP response may trigger one TCP
    /// continuation within the same attempt deadline. Scoped IPv6 link-local
    /// servers require UDP-only mode because [`Target`] does not carry a TCP
    /// scope identifier.
    pub tcp_fallback: bool,
    pub attempts: u32,
    pub timeout: Duration,
    pub queries_per_second: Option<u32>,
    pub limits: Limits,
}

impl Request {
    /// Rejects every request this workflow cannot execute: an out-of-range
    /// limit, port, attempt count, timeout, or rate, and a query name that is
    /// not a valid DNS name, or invalid EDNS request settings.
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if let Some(edns) = self.edns {
            edns.validate().map_err(Error::Query)?;
        }
        if self.server_port == 0 {
            return Err(Error::InvalidPort);
        }
        if self.source_port == 0 {
            return Err(Error::InvalidSourcePort);
        }
        if !(1..=MAX_ATTEMPTS).contains(&self.attempts) {
            return Err(Error::InvalidLimit {
                field: "attempts",
                value: u64::from(self.attempts),
                reason: format!("must be within 1..={MAX_ATTEMPTS}"),
            });
        }
        if self.timeout.is_zero() || self.timeout > packetcraftr_netio::capture::MAX_TIMEOUT {
            return Err(Error::InvalidTimeout {
                value: self.timeout,
                maximum: packetcraftr_netio::capture::MAX_TIMEOUT,
            });
        }
        if let Some(rate) = self.queries_per_second
            && (rate == 0 || rate > MAX_RATE)
        {
            return Err(Error::InvalidLimit {
                field: "queries_per_second",
                value: u64::from(rate),
                reason: format!("must be within 1..={MAX_RATE}"),
            });
        }
        canonical_query_name(&self.query_name).map_err(Error::Query)?;
        Ok(())
    }

    /// The canonical wire form of the declared query name, after
    /// [`Request::validate`] accepts the request.
    pub fn canonical_name(&self) -> Result<String, Error> {
        self.validate()?;
        canonical_query_name(&self.query_name).map_err(Error::Query)
    }
}

impl From<MessageLimits> for packetcraftr_core::protocol::application::dns::DecodeLimits {
    fn from(limits: MessageLimits) -> Self {
        Self {
            max_message_bytes: limits.max_message_bytes,
            max_records: limits.max_records,
            max_name_pointers: limits.max_name_pointers,
            max_txt_strings: limits.max_txt_strings,
            max_txt_bytes: limits.max_txt_bytes,
        }
    }
}

#[cfg(test)]
mod query_type_tests {
    use super::{QueryType, QueryTypeParseError};

    #[test]
    fn aliases_and_numeric_syntax_share_exact_codes_and_canonical_display() {
        for (alias, code) in [
            ("a", 1),
            ("aaaa", 28),
            ("caa", 257),
            ("cname", 5),
            ("mx", 15),
            ("ns", 2),
            ("ptr", 12),
            ("soa", 6),
            ("srv", 33),
            ("txt", 16),
            ("any", 255),
        ] {
            for text in [
                alias.to_owned(),
                alias.to_uppercase(),
                code.to_string(),
                format!("TyPe{code}"),
            ] {
                let parsed: QueryType = text.parse().expect("supported query type");
                assert_eq!(parsed.code(), code);
                assert_eq!(parsed.to_string(), alias);
            }
        }
        for code in [0, 41, 65000, 65535] {
            let parsed: QueryType = format!("TYPE{code}").parse().unwrap();
            assert_eq!(parsed, QueryType::new(code));
            assert_eq!(parsed.to_string(), format!("TYPE{code}"));
            assert_eq!(serde_json::to_value(parsed).unwrap(), code);
            assert_eq!(
                serde_json::from_str::<QueryType>(&code.to_string()).unwrap(),
                parsed
            );
        }
        assert_eq!("00001".parse::<QueryType>().unwrap(), QueryType::default());
    }

    #[test]
    fn invalid_query_types_are_bounded_and_typed() {
        for text in [
            "",
            "TYPE",
            "TYPE-1",
            "-1",
            "+1",
            "1.0",
            "0x1",
            " 1",
            "1 ",
            "１",
            "type１２",
            "000001",
            "TYPE000001",
            "unknown",
        ] {
            assert!(
                matches!(text.parse::<QueryType>(), Err(QueryTypeParseError::Syntax)),
                "{text:?}"
            );
        }
        for text in ["65536", "TYPE65536", "99999"] {
            let error = text.parse::<QueryType>().unwrap_err();
            assert!(matches!(error, QueryTypeParseError::OutOfRange(_)));
            assert!(
                std::error::Error::source(&error)
                    .unwrap()
                    .is::<std::num::ParseIntError>()
            );
        }
        for json in ["-1", "65536", "1.5", "\"a\"", "\"65000\""] {
            assert!(serde_json::from_str::<QueryType>(json).is_err());
        }
    }
}
