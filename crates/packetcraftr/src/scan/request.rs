// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_core::template::DEFAULT_MAX_TEMPLATE_PACKETS;
use packetcraftr_netio::capture::{MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES, MAX_TIMEOUT};

use crate::probe::evidence::EvidenceLimits;
use crate::probe::limits::{check_limits, duration_violation};
use crate::target::Family;
use crate::target::Selection;

use crate::probe::{Error, ErrorKind, Transport};
use crate::scan::WORKFLOW;
use crate::scan::{
    DEFAULT_MAX_PORTS, DEFAULT_MAX_UNDECODED_FRAMES, MAX_ATTEMPTS, MAX_PROBES, MAX_RATE,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_prepared_bytes: usize,
    pub max_targets: usize,
    pub max_ports: usize,
    pub max_probes: usize,
    pub max_duration: Duration,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_undecoded: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_prepared_bytes: 64 * 1024 * 1024,
            max_targets: 1024,
            max_ports: DEFAULT_MAX_PORTS,
            max_probes: DEFAULT_MAX_TEMPLATE_PACKETS,
            max_duration: MAX_TIMEOUT,
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
                (
                    "max_prepared_bytes",
                    self.max_prepared_bytes,
                    256 * 1024 * 1024,
                ),
                ("max_targets", self.max_targets, super::MAX_PROBES),
                ("max_ports", self.max_ports, usize::from(u16::MAX) + 1),
                ("max_probes", self.max_probes, MAX_PROBES),
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
        if duration_violation(self.max_duration, MAX_TIMEOUT) {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidDuration {
                    value: self.max_duration,
                    maximum: MAX_TIMEOUT,
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

/// Expands selections in first-seen order, deduplicating without charging
/// repeats. Stops before adding a distinct port beyond `max_ports`.
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
    /// Maximum overlapping probe response windows.
    pub max_in_flight: usize,
    pub targets: Selection,
    pub transport: Transport,
    /// Exact bytes appended to each UDP probe; empty preserves an empty datagram.
    /// Non-empty payloads are rejected for TCP and ICMP.
    #[serde(default)]
    pub udp_payload: bytes::Bytes,
    #[serde(default)]
    pub udp_profiles: std::collections::BTreeMap<u16, std::sync::Arc<super::profile::UdpProfile>>,
    pub address_family: Family,
    /// TCP or UDP destination ports. ICMP scans require this to be empty and
    /// produce one portless endpoint per selected address.
    pub ports: Vec<u16>,
    pub attempts: u32,
    pub timeout: Duration,
    /// Maximum probe start rate; rolling windows share one pacing schedule.
    pub probes_per_second: Option<u32>,
    pub limits: Limits,
}

impl Request {
    /// Rejects every request this workflow cannot execute: an out-of-range
    /// limit, attempt count, timeout, or rate, and a transport that disagrees
    /// with the declared ports.
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if self.max_in_flight == 0 || self.max_in_flight > 1024 {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "max_in_flight",
                    value: self.max_in_flight as u64,
                    reason: "must be within 1..=1024".to_owned(),
                },
            ));
        }
        self.targets
            .validate()
            .map_err(|source| Error::new(WORKFLOW, ErrorKind::TargetSelection(source)))?;
        if self.udp_profiles.len() > super::profile::MAX_PROFILE_PORTS
            || (!self.udp_profiles.is_empty() && self.transport != Transport::Udp)
        {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "udp_profiles",
                    value: self.udp_profiles.len() as u64,
                    reason: "profiles require UDP and at most 4096 port mappings".to_owned(),
                },
            ));
        }
        let mut seen_profiles = std::collections::HashSet::new();
        let mut profile_bytes = 0usize;
        for profile in self.udp_profiles.values() {
            if seen_profiles.insert(std::sync::Arc::as_ptr(profile)) {
                profile_bytes = profile_bytes.saturating_add(profile.storage_bytes());
            }
        }
        if profile_bytes > super::profile::MAX_PROFILE_BYTES {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "udp_profile_bytes",
                    value: profile_bytes as u64,
                    reason: "compiled profiles exceed 1 MiB".to_owned(),
                },
            ));
        }
        if self.udp_payload.len() > super::MAX_UDP_PAYLOAD_BYTES
            || (!self.udp_payload.is_empty() && self.transport != Transport::Udp)
        {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "udp_payload_bytes",
                    value: u64::try_from(self.udp_payload.len()).unwrap_or(u64::MAX),
                    reason: format!(
                        "UDP scans accept at most {} payload bytes; TCP and ICMP require an empty payload",
                        super::MAX_UDP_PAYLOAD_BYTES
                    ),
                },
            ));
        }
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
        if self.timeout.is_zero() || self.timeout > MAX_TIMEOUT {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidTimeout {
                    value: self.timeout,
                    maximum: MAX_TIMEOUT,
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
