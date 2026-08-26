// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_netio::capture::{DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES};

use crate::probe::evidence::{check_limits, duration_violation};
use crate::target::Family;
use crate::target::Target;

use super::super::error::Error;
use super::super::wire::canonical_query_name;
use super::super::{
    DEFAULT_MAX_DNS_NAME_POINTERS, DEFAULT_MAX_DNS_RECORDS, DEFAULT_MAX_DNS_TXT_BYTES,
    DEFAULT_MAX_DNS_TXT_STRINGS, DEFAULT_MAX_REJECTED_DNS_RECORDS,
    DEFAULT_MAX_UNDECODED_DNS_FRAMES, MAX_DNS_ATTEMPTS, MAX_DNS_DURATION, MAX_DNS_MESSAGE_BYTES,
    MAX_DNS_NAME_POINTERS, MAX_DNS_RATE, MAX_DNS_RECORDS,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryType {
    #[default]
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Soa,
    Srv,
    Txt,
    Any,
}

impl QueryType {
    pub const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Any => 255,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::Aaaa => "aaaa",
            Self::Cname => "cname",
            Self::Mx => "mx",
            Self::Ns => "ns",
            Self::Ptr => "ptr",
            Self::Soa => "soa",
            Self::Srv => "srv",
            Self::Txt => "txt",
            Self::Any => "any",
        }
    }
}

impl fmt::Display for QueryType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_message_bytes: usize,
    pub max_records: usize,
    pub max_name_pointers: usize,
    pub max_txt_strings: usize,
    pub max_txt_bytes: usize,
    pub max_rejected_records: usize,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_undecoded: usize,
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_bytes: MAX_DNS_MESSAGE_BYTES,
            max_records: DEFAULT_MAX_DNS_RECORDS,
            max_name_pointers: DEFAULT_MAX_DNS_NAME_POINTERS,
            max_txt_strings: DEFAULT_MAX_DNS_TXT_STRINGS,
            max_txt_bytes: DEFAULT_MAX_DNS_TXT_BYTES,
            max_rejected_records: DEFAULT_MAX_REJECTED_DNS_RECORDS,
            max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            max_undecoded: DEFAULT_MAX_UNDECODED_DNS_FRAMES,
            max_duration: MAX_DNS_DURATION,
        }
    }
}

impl Limits {
    pub fn validate(self) -> std::result::Result<Self, Error> {
        check_limits(
            &[
                (
                    "max_message_bytes",
                    self.max_message_bytes,
                    MAX_DNS_MESSAGE_BYTES,
                ),
                ("max_records", self.max_records, MAX_DNS_RECORDS),
                (
                    "max_name_pointers",
                    self.max_name_pointers,
                    MAX_DNS_NAME_POINTERS,
                ),
                ("max_txt_strings", self.max_txt_strings, MAX_DNS_RECORDS),
                ("max_txt_bytes", self.max_txt_bytes, MAX_DNS_MESSAGE_BYTES),
                (
                    "max_evidence_frames",
                    self.max_evidence_frames,
                    DEFAULT_CAPTURE_QUEUE_FRAMES,
                ),
                (
                    "max_evidence_bytes",
                    self.max_evidence_bytes,
                    DEFAULT_CAPTURE_QUEUE_BYTES,
                ),
            ],
            &[
                (
                    "max_rejected_records",
                    self.max_rejected_records,
                    self.max_records,
                    "cannot exceed max_records",
                ),
                (
                    "max_undecoded",
                    self.max_undecoded,
                    self.max_evidence_frames,
                    "cannot exceed max_evidence_frames",
                ),
            ],
            |field, value, reason| Error::InvalidLimit {
                field,
                value,
                reason,
            },
        )?;
        if duration_violation(self.max_duration, MAX_DNS_DURATION) {
            return Err(Error::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_DNS_DURATION,
            });
        }
        Ok(self)
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
    pub attempts: u32,
    pub timeout: Duration,
    pub queries_per_second: Option<u32>,
    pub limits: Limits,
}

impl Request {
    pub fn validate(&self) -> std::result::Result<String, Error> {
        self.limits.validate()?;
        if self.server_port == 0 {
            return Err(Error::InvalidPort);
        }
        if self.source_port == 0 {
            return Err(Error::InvalidSourcePort);
        }
        if !(1..=MAX_DNS_ATTEMPTS).contains(&self.attempts) {
            return Err(Error::InvalidLimit {
                field: "attempts",
                value: u64::from(self.attempts),
                reason: format!("must be within 1..={MAX_DNS_ATTEMPTS}"),
            });
        }
        if self.timeout.is_zero() || self.timeout > packetcraftr_netio::capture::MAX_TIMEOUT {
            return Err(Error::InvalidTimeout {
                value: self.timeout,
                maximum: packetcraftr_netio::capture::MAX_TIMEOUT,
            });
        }
        if let Some(rate) = self.queries_per_second
            && (rate == 0 || rate > MAX_DNS_RATE)
        {
            return Err(Error::InvalidLimit {
                field: "queries_per_second",
                value: u64::from(rate),
                reason: format!("must be within 1..={MAX_DNS_RATE}"),
            });
        }
        canonical_query_name(&self.query_name).map_err(Error::Query)
    }
}
