// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_core::template::DEFAULT_MAX_TEMPLATE_PACKETS;
use packetcraftr_netio::capture::{MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES};

use crate::probe::evidence::{EvidenceLimits, check_limits, duration_violation};
use crate::target::Family;
use crate::target::Target;

use crate::probe::{Error, ErrorKind};
use crate::scan::WORKFLOW;
use crate::scan::{
    DEFAULT_BATCH_SIZE, DEFAULT_MAX_PORTS, DEFAULT_MAX_UNDECODED_FRAMES, MAX_ATTEMPTS,
    MAX_DURATION, MAX_PROBES, MAX_RATE,
};

pub use crate::probe::Transport;

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
            max_ports: DEFAULT_MAX_PORTS,
            max_probes: DEFAULT_MAX_TEMPLATE_PACKETS,
            batch_size: DEFAULT_BATCH_SIZE,
            max_duration: MAX_DURATION,
            max_evidence_frames: MAX_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: MAX_CAPTURE_QUEUE_BYTES,
            max_undecoded: DEFAULT_MAX_UNDECODED_FRAMES,
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

    /// Rejects any bound above the ceiling this crate enforces, and any pair
    /// of bounds that cannot both hold.
    pub fn validate(&self) -> Result<(), Error> {
        check_limits(
            &[
                ("max_ports", self.max_ports, usize::from(u16::MAX) + 1),
                ("max_probes", self.max_probes, MAX_PROBES),
                ("batch_size", self.batch_size, MAX_PROBES),
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
            &[
                (
                    "batch_size",
                    self.batch_size,
                    self.max_probes,
                    "cannot exceed max_probes",
                ),
                (
                    "batch_size",
                    self.batch_size,
                    self.max_evidence_frames,
                    "cannot exceed max_evidence_frames because every probe may receive a response",
                ),
                (
                    "max_undecoded",
                    self.max_undecoded,
                    self.max_evidence_frames,
                    "cannot exceed max_evidence_frames",
                ),
            ],
            |field, value, reason| {
                Error::new(
                    WORKFLOW,
                    ErrorKind::InvalidLimit {
                        field,
                        value,
                        reason,
                    },
                )
            },
        )?;
        if duration_violation(self.max_duration, MAX_DURATION) {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidDuration {
                    value: self.max_duration,
                    maximum: MAX_DURATION,
                },
            ));
        }
        Ok(())
    }
}

/// One requested destination-port selection: a single port, or an inclusive
/// range. A range whose `end` precedes its `start` selects nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortSpec {
    Single(u16),
    RangeInclusive { start: u16, end: u16 },
}

/// Expands port selections into the stable, de-duplicated destination-port
/// list a [`Request`] carries, enforcing `max_ports` as it goes.
///
/// Ports keep their first-seen order; a repeated port or an overlapping range
/// collapses and does not consume the budget. Expansion stops at the first
/// distinct port that would exceed `max_ports`, so an oversized range is never
/// materialized.
pub fn select_ports(
    specs: impl IntoIterator<Item = PortSpec>,
    max_ports: usize,
) -> Result<Vec<u16>, Error> {
    let mut ports: Vec<u16> = Vec::new();
    let mut seen: HashSet<u16> = HashSet::new();
    for spec in specs {
        let (start, end) = match spec {
            PortSpec::Single(port) => (port, port),
            PortSpec::RangeInclusive { start, end } => (start, end),
        };
        for port in start..=end {
            if !seen.insert(port) {
                continue;
            }
            if ports.len() >= max_ports {
                return Err(Error::new(
                    WORKFLOW,
                    ErrorKind::InvalidLimit {
                        field: "ports",
                        value: u64::try_from(ports.len())
                            .unwrap_or(u64::MAX)
                            .saturating_add(1),
                        reason: format!("exceeds max_ports={max_ports}"),
                    },
                ));
            }
            ports.push(port);
        }
    }
    Ok(ports)
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
    /// Rejects every request this workflow cannot execute: an out-of-range
    /// limit, attempt count, timeout, or rate, and a transport that disagrees
    /// with the declared ports.
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if !(1..=MAX_ATTEMPTS).contains(&self.attempts) {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "attempts",
                    value: u64::from(self.attempts),
                    reason: format!("must be within 1..={MAX_ATTEMPTS}"),
                },
            ));
        }
        if self.timeout.is_zero() || self.timeout > packetcraftr_netio::capture::MAX_TIMEOUT {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidTimeout {
                    value: self.timeout,
                    maximum: packetcraftr_netio::capture::MAX_TIMEOUT,
                },
            ));
        }
        if let Some(rate) = self.probes_per_second
            && (rate == 0 || rate > MAX_RATE)
        {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "probes_per_second",
                    value: u64::from(rate),
                    reason: format!("must be within 1..={MAX_RATE}"),
                },
            ));
        }
        match self.transport {
            Transport::Tcp | Transport::Udp if self.ports.is_empty() => {
                return Err(Error::new(
                    WORKFLOW,
                    ErrorKind::InvalidPort {
                        message: "TCP and UDP scans require at least one destination port"
                            .to_owned(),
                    },
                ));
            }
            Transport::Icmp if !self.ports.is_empty() => {
                return Err(Error::new(
                    WORKFLOW,
                    ErrorKind::InvalidPort {
                        message: "ICMP scans are portless and do not accept destination ports"
                            .to_owned(),
                    },
                ));
            }
            _ => {}
        }
        Ok(())
    }

    /// The de-duplicated destination ports this request scans, in first-seen
    /// order, after [`Request::validate`] accepts it. Empty for ICMP.
    pub fn selected_ports(&self) -> Result<Vec<u16>, Error> {
        self.validate()?;
        select_ports(
            self.ports.iter().copied().map(PortSpec::Single),
            self.limits.max_ports,
        )
    }
}
