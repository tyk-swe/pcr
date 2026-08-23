// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_core::template::DEFAULT_MAX_TEMPLATE_PACKETS;
use packetcraftr_netio::capture::{DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES};

use crate::target::Family;
use crate::target::Target;

use super::super::{
    DEFAULT_MAX_SCAN_PORTS, DEFAULT_MAX_UNDECODED_SCAN_FRAMES, DEFAULT_SCAN_BATCH_SIZE,
    MAX_SCAN_ATTEMPTS, MAX_SCAN_DURATION, MAX_SCAN_PROBES, MAX_SCAN_RATE,
};
use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
}

impl Transport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }

    pub(in crate::scan) const fn probe_transport(self) -> crate::probe::Transport {
        match self {
            Self::Tcp => crate::probe::Transport::Tcp,
            Self::Udp => crate::probe::Transport::Udp,
            Self::Icmp => crate::probe::Transport::Icmp,
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_ports: usize,
    pub max_probes: usize,
    pub batch_size: usize,
    pub max_duration: Duration,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_undecoded: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_ports: DEFAULT_MAX_SCAN_PORTS,
            max_probes: DEFAULT_MAX_TEMPLATE_PACKETS,
            batch_size: DEFAULT_SCAN_BATCH_SIZE,
            max_duration: MAX_SCAN_DURATION,
            max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            max_undecoded: DEFAULT_MAX_UNDECODED_SCAN_FRAMES,
        }
    }
}

impl Limits {
    pub fn validate(self) -> std::result::Result<Self, Error> {
        for (field, value, maximum) in [
            ("max_ports", self.max_ports, usize::from(u16::MAX) + 1),
            ("max_probes", self.max_probes, MAX_SCAN_PROBES),
            ("batch_size", self.batch_size, MAX_SCAN_PROBES),
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
                return Err(Error::InvalidRequest {
                    field,
                    message: format!("must be within 1..={maximum}; received {value}"),
                });
            }
        }
        if self.batch_size > self.max_probes {
            return Err(Error::InvalidRequest {
                field: "batch_size",
                message: format!("cannot exceed max_probes; received {}", self.batch_size),
            });
        }
        if self.batch_size > self.max_evidence_frames {
            return Err(Error::InvalidRequest {
                field: "batch_size",
                message: format!(
                    "cannot exceed max_evidence_frames because every probe may receive a response; received {}",
                    self.batch_size
                ),
            });
        }
        if self.max_undecoded > self.max_evidence_frames {
            return Err(Error::InvalidRequest {
                field: "max_undecoded",
                message: format!(
                    "cannot exceed max_evidence_frames; received {}",
                    self.max_undecoded
                ),
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_SCAN_DURATION {
            return Err(Error::InvalidRequest {
                field: "max_duration",
                message: format!(
                    "must be finite, non-zero, and no greater than {MAX_SCAN_DURATION:?}; received {:?}",
                    self.max_duration
                ),
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub target: Target,
    pub transport: Transport,
    pub address_family: Family,
    /// TCP or UDP destination ports. ICMP scans require this to be empty and
    /// produce one portless endpoint per selected address.
    pub ports: Vec<u16>,
    pub attempts: u32,
    pub timeout: Duration,
    /// Maximum average probe rate. Batches are deliberate bursts and the
    /// clock spaces their start times by the preceding batch's probe count.
    pub probes_per_second: Option<u32>,
    pub limits: Limits,
}

impl Request {
    pub(in crate::scan) fn validate(&self) -> std::result::Result<Vec<u16>, Error> {
        self.limits.validate()?;
        if !(1..=MAX_SCAN_ATTEMPTS).contains(&self.attempts) {
            return Err(Error::InvalidRequest {
                field: "attempts",
                message: format!(
                    "must be within 1..={MAX_SCAN_ATTEMPTS}; received {}",
                    self.attempts
                ),
            });
        }
        if self.timeout.is_zero() || self.timeout > packetcraftr_netio::capture::MAX_TIMEOUT {
            return Err(Error::InvalidRequest {
                field: "timeout",
                message: format!(
                    "must be finite, non-zero, and no greater than {:?}; received {:?}",
                    packetcraftr_netio::capture::MAX_TIMEOUT,
                    self.timeout
                ),
            });
        }
        if let Some(rate) = self.probes_per_second
            && (rate == 0 || rate > MAX_SCAN_RATE)
        {
            return Err(Error::InvalidRequest {
                field: "probes_per_second",
                message: format!("must be within 1..={MAX_SCAN_RATE}; received {rate}"),
            });
        }
        match self.transport {
            Transport::Tcp | Transport::Udp if self.ports.is_empty() => {
                return Err(Error::InvalidRequest {
                    field: "ports",
                    message: "TCP and UDP scans require at least one destination port".to_owned(),
                });
            }
            Transport::Icmp if !self.ports.is_empty() => {
                return Err(Error::InvalidRequest {
                    field: "ports",
                    message: "ICMP scans are portless and do not accept destination ports"
                        .to_owned(),
                });
            }
            _ => {}
        }
        let mut ports = Vec::with_capacity(self.ports.len());
        let mut seen_ports = HashSet::with_capacity(self.ports.len());
        for port in &self.ports {
            if seen_ports.insert(*port) {
                ports.push(*port);
            }
        }
        if ports.len() > self.limits.max_ports {
            return Err(Error::InvalidRequest {
                field: "ports",
                message: format!(
                    "exceeds max_ports={}; received {}",
                    self.limits.max_ports,
                    ports.len()
                ),
            });
        }
        Ok(ports)
    }
}
