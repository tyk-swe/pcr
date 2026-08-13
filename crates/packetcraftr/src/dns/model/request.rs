// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_netio::capture::{DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES};

use crate::scan::MAX_SCAN_RATE;
use crate::target::Family;
use crate::target::Target;

use super::super::error::DnsError;
use super::super::wire::canonical_query_name;
use super::super::{
    DEFAULT_MAX_DNS_NAME_POINTERS, DEFAULT_MAX_DNS_RECORDS, DEFAULT_MAX_DNS_TXT_BYTES,
    DEFAULT_MAX_DNS_TXT_STRINGS, DEFAULT_MAX_REJECTED_DNS_RECORDS,
    DEFAULT_MAX_UNDECODED_DNS_FRAMES, MAX_DNS_ATTEMPTS, MAX_DNS_DURATION, MAX_DNS_MESSAGE_BYTES,
    MAX_DNS_NAME_POINTERS, MAX_DNS_RECORDS,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsQueryType {
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

impl DnsQueryType {
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

impl fmt::Display for DnsQueryType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsLimits {
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

impl Default for DnsLimits {
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

impl DnsLimits {
    pub fn validate(self) -> std::result::Result<Self, DnsError> {
        for (field, value, maximum) in [
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
        ] {
            if value == 0 || value > maximum {
                return Err(DnsError::InvalidLimit {
                    field,
                    value: u64::try_from(value).unwrap_or(u64::MAX),
                    reason: format!("must be within 1..={maximum}"),
                });
            }
        }
        if self.max_rejected_records > self.max_records {
            return Err(DnsError::InvalidLimit {
                field: "max_rejected_records",
                value: u64::try_from(self.max_rejected_records).unwrap_or(u64::MAX),
                reason: "cannot exceed max_records".to_owned(),
            });
        }
        if self.max_undecoded > self.max_evidence_frames {
            return Err(DnsError::InvalidLimit {
                field: "max_undecoded",
                value: u64::try_from(self.max_undecoded).unwrap_or(u64::MAX),
                reason: "cannot exceed max_evidence_frames".to_owned(),
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_DNS_DURATION {
            return Err(DnsError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_DNS_DURATION,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRequest {
    pub server: Target,
    pub address_family: Family,
    pub server_port: u16,
    pub source_port: u16,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub transaction_id: u16,
    pub recursion_desired: bool,
    pub attempts: u32,
    pub timeout: Duration,
    pub queries_per_second: Option<u32>,
    pub limits: DnsLimits,
}

impl DnsRequest {
    pub fn validate(&self) -> std::result::Result<String, DnsError> {
        self.limits.validate()?;
        if self.server_port == 0 {
            return Err(DnsError::InvalidPort);
        }
        if self.source_port == 0 {
            return Err(DnsError::InvalidSourcePort);
        }
        if !(1..=MAX_DNS_ATTEMPTS).contains(&self.attempts) {
            return Err(DnsError::InvalidLimit {
                field: "attempts",
                value: u64::from(self.attempts),
                reason: format!("must be within 1..={MAX_DNS_ATTEMPTS}"),
            });
        }
        if self.timeout.is_zero() || self.timeout > packetcraftr_netio::capture::MAX_TIMEOUT {
            return Err(DnsError::InvalidTimeout {
                value: self.timeout,
                maximum: packetcraftr_netio::capture::MAX_TIMEOUT,
            });
        }
        if let Some(rate) = self.queries_per_second
            && (rate == 0 || rate > MAX_SCAN_RATE)
        {
            return Err(DnsError::InvalidLimit {
                field: "queries_per_second",
                value: u64::from(rate),
                reason: format!("must be within 1..={MAX_SCAN_RATE}"),
            });
        }
        canonical_query_name(&self.query_name).map_err(DnsError::Query)
    }
}
