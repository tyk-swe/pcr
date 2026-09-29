// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_netio::capture::{MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES};
use packetcraftr_netio::deadline::MAX_WAIT;

use crate::execution::limits::EvidenceLimits;
use crate::execution::limits::{check_limits, check_rate, duration_violation};
use crate::target::Family;
use crate::target::Target;

use super::Error;
use super::error::Probes;
use crate::probe::Transport;
use crate::traceroute::{DEFAULT_MAX_UNDECODED_FRAMES, MAX_PROBES, MAX_PROBES_PER_HOP};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_probes: usize,
    pub max_duration: Duration,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_undecoded: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_probes: packetcraftr_core::template::DEFAULT_MAX_TEMPLATE_PACKETS,
            max_duration: MAX_WAIT,
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

    pub fn validate(&self) -> Result<(), Error> {
        check_limits(
            &[("max_probes", self.max_probes, MAX_PROBES)],
            &[],
            |field, value, reason| Error::InvalidLimit {
                field,
                value,
                reason,
            },
        )?;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub target: Target,
    pub strategy: Transport,
    pub udp_port_mode: super::UdpPortMode,
    pub cycles: u32,
    pub cycle_interval: Duration,
    pub address_family: Family,
    /// UDP base destination port or fixed TCP destination port. ICMP requires
    /// this to be absent.
    pub destination_port: Option<u16>,
    pub source_port: Option<u16>,
    pub first_hop: u8,
    pub max_hops: u8,
    pub probes_per_hop: u32,
    pub timeout: Duration,
    pub probes_per_second: Option<u32>,
    pub limits: Limits,
    pub route: crate::route::Options,
    /// It must retain at least one response per probe of a hop.
    pub collection: crate::exchange::Collection,
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if self.cycles == 0 || self.cycles > 1024 {
            return Err(Error::InvalidLimit {
                field: "cycles",
                value: u64::from(self.cycles),
                reason: "must be within 1..=1024".to_owned(),
            });
        }
        if self.cycles > 1
            && self.cycle_interval.saturating_mul(self.cycles - 1) > self.limits.max_duration
        {
            return Err(Error::InvalidDuration {
                value: self.cycle_interval,
                maximum: self.limits.max_duration,
            });
        }
        if self.udp_port_mode == super::UdpPortMode::Fixed && self.strategy != Transport::Udp {
            return Err(Error::InvalidPort {
                message: "fixed UDP ports require UDP traceroute".to_owned(),
            });
        }
        if self.first_hop == 0 {
            return Err(Error::InvalidLimit {
                field: "first_hop",
                value: 0,
                reason: "must be within 1..=255".to_owned(),
            });
        }
        if self.max_hops < self.first_hop {
            return Err(Error::InvalidLimit {
                field: "max_hops",
                value: u64::from(self.max_hops),
                reason: format!("must be at least first_hop={}", self.first_hop),
            });
        }
        if !(1..=MAX_PROBES_PER_HOP).contains(&self.probes_per_hop) {
            return Err(Error::InvalidLimit {
                field: "probes_per_hop",
                value: u64::from(self.probes_per_hop),
                reason: format!("must be within 1..={MAX_PROBES_PER_HOP}"),
            });
        }
        if usize::try_from(self.probes_per_hop).unwrap_or(usize::MAX)
            > self.limits.max_evidence_frames
        {
            return Err(Error::InvalidLimit {
                field: "probes_per_hop",
                value: u64::from(self.probes_per_hop),
                reason: format!(
                    "cannot exceed max_evidence_frames={} because every probe may receive a response",
                    self.limits.max_evidence_frames
                ),
            });
        }
        if duration_violation(self.timeout, MAX_WAIT) {
            return Err(Error::InvalidTimeout {
                value: self.timeout,
                maximum: MAX_WAIT,
            });
        }
        check_rate(&Probes, "probes_per_second", self.probes_per_second)?;
        match (self.strategy, self.destination_port) {
            (Transport::Udp | Transport::Tcp, None) => {
                return Err(Error::InvalidPort {
                    message: "UDP and TCP traceroute require a destination port".to_owned(),
                });
            }
            (Transport::Udp | Transport::Tcp, Some(0)) => {
                return Err(Error::InvalidPort {
                    message: "UDP and TCP traceroute require a non-zero destination port"
                        .to_owned(),
                });
            }
            (Transport::Icmp, Some(_)) => {
                return Err(Error::InvalidPort {
                    message: "ICMP traceroute is portless".to_owned(),
                });
            }
            _ => {}
        }
        if self.source_port == Some(0)
            || (self.strategy == Transport::Icmp && self.source_port.is_some())
        {
            return Err(Error::InvalidSourcePort);
        }
        Ok(())
    }

    // `validate` rejects `max_hops < first_hop`, so the u8 subtraction cannot underflow, and a u8
    // widened to usize leaves room for the increment
    pub(in crate::traceroute) fn hop_count(&self) -> usize {
        usize::from(self.max_hops - self.first_hop) + 1
    }

    pub(in crate::traceroute) fn total_probe_count(&self) -> Result<usize, Error> {
        self.hop_count()
            .checked_mul(usize::try_from(self.probes_per_hop).unwrap_or(usize::MAX))
            .and_then(|count| count.checked_mul(self.cycles as usize))
            .ok_or(Error::InvalidLimit {
                field: "probes",
                value: u64::MAX,
                reason: "probe-count arithmetic overflowed".to_owned(),
            })
    }
}
