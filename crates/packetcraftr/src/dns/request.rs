// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_netio::capture::{MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES};
use packetcraftr_netio::deadline::MAX_WAIT;

use crate::execution::limits::EvidenceLimits;
use crate::execution::limits::{check_limits, check_rate, duration_violation};
use crate::target::Family;
use crate::target::Target;

use crate::dns::error::{Attempts, Error};
use crate::dns::wire::{self, canonical_query_name};
use crate::dns::{
    DEFAULT_MAX_NAME_POINTERS, DEFAULT_MAX_RECORDS, DEFAULT_MAX_REJECTED_RECORDS,
    DEFAULT_MAX_TXT_BYTES, DEFAULT_MAX_TXT_STRINGS, DEFAULT_MAX_UNDECODED_FRAMES, MAX_ATTEMPTS,
    MAX_MESSAGE_BYTES, MAX_NAME_POINTERS, MAX_RECORDS,
};

/// A DNS question's exact 16-bit wire code, including unassigned codes.
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

impl std::str::FromStr for QueryType {
    type Err = wire::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > 9 {
            return Err(wire::Error::QueryTypeSyntax);
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
            return Err(wire::Error::QueryTypeSyntax);
        }
        digits
            .parse()
            .map(Self)
            .map_err(wire::Error::QueryTypeRange)
    }
}

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
            max_duration: MAX_WAIT,
        }
    }
}

impl Limits {
    pub(crate) const fn evidence(&self) -> EvidenceLimits {
        EvidenceLimits {
            max_frames: self.max_evidence_frames,
            max_bytes: self.max_evidence_bytes,
            max_undecoded: self.max_undecoded,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.message.validate()?;
        self.evidence()
            .validate(|field, value, reason| Error::InvalidLimit {
                field,
                value,
                reason,
            })?;
        if duration_violation(self.max_duration, MAX_WAIT) {
            return Err(Error::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_WAIT,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdnsRequest {
    /// Advertised UDP response capacity; it does not change capture or decoding limits.
    pub udp_payload_size: u16,
    /// Request DNSSEC records; this does not perform signature validation.
    pub dnssec_ok: bool,
}

impl EdnsRequest {
    pub fn validate(&self) -> Result<(), wire::Error> {
        if self.udp_payload_size < 512 {
            return Err(wire::Error::InvalidEdns {
                message: format!(
                    "request UDP payload size {} must be within 512..=65535",
                    self.udp_payload_size
                ),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    #[default]
    UdpThenTcp,
    Udp,
    Tcp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub server: Target,
    pub address_family: Family,
    pub server_port: u16,
    /// Initial UDP source port; unused in TCP-only mode.
    pub source_port: u16,
    pub query_name: String,
    pub query_type: QueryType,
    pub transaction_id: u16,
    pub recursion_desired: bool,
    #[serde(default)]
    pub edns: Option<EdnsRequest>,
    /// Scoped IPv6 link-local servers need UDP: [`Target`] carries no TCP scope identifier.
    #[serde(default)]
    pub transport: TransportMode,
    pub attempts: u32,
    pub timeout: Duration,
    pub queries_per_second: Option<u32>,
    pub limits: Limits,
    /// Direct TCP and fallback run on a kernel socket, which accepts only default route options.
    #[serde(skip)]
    pub route: crate::route::Options,
    /// Must fit inside [`Limits`]'s evidence bounds.
    #[serde(skip)]
    pub collection: crate::exchange::Collection,
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if let Some(edns) = self.edns {
            edns.validate().map_err(Error::Query)?;
        }
        if self.server_port == 0 {
            return Err(Error::InvalidPort);
        }
        if self.transport != TransportMode::Tcp && self.source_port == 0 {
            return Err(Error::InvalidSourcePort);
        }
        if self.transport != TransportMode::Udp && self.route.requires_packet_route() {
            return Err(Error::UnsupportedTcpRoute);
        }
        if !(1..=MAX_ATTEMPTS).contains(&self.attempts) {
            return Err(Error::InvalidLimit {
                field: "attempts",
                value: u64::from(self.attempts),
                reason: format!("must be within 1..={MAX_ATTEMPTS}"),
            });
        }
        if duration_violation(self.timeout, MAX_WAIT) {
            return Err(Error::InvalidTimeout {
                value: self.timeout,
                maximum: MAX_WAIT,
            });
        }
        check_rate(&Attempts, "queries_per_second", self.queries_per_second)?;
        canonical_query_name(&self.query_name).map_err(Error::Query)?;
        Ok(())
    }

    pub fn canonical_name(&self) -> Result<String, Error> {
        self.validate()?;
        canonical_query_name(&self.query_name).map_err(Error::Query)
    }

    /// Checks the UDP executor's capture requirements before a composed
    /// workflow starts any earlier stage. TCP queries do not use capture.
    pub(crate) fn validate_capture(&self) -> Result<(), Error> {
        if self.transport != TransportMode::Tcp {
            super::executor::validate_capture(&self.limits, &self.collection)
                .map_err(|source| Error::Execution { attempt: 1, source })?;
        }
        Ok(())
    }
}

impl From<MessageLimits> for packetcraftr_core::protocol::application::dns::Limits {
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
mod tests {
    use super::{QueryType, wire};

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
                matches!(text.parse::<QueryType>(), Err(wire::Error::QueryTypeSyntax)),
                "{text:?}"
            );
        }
        for text in ["65536", "TYPE65536", "99999"] {
            let error = text.parse::<QueryType>().unwrap_err();
            assert!(matches!(error, wire::Error::QueryTypeRange(_)));
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
