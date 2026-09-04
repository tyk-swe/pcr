// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_netio::capture::{MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES};

use crate::probe::evidence::{EvidenceLimits, check_limits, duration_violation};
use crate::target::Family;
use crate::target::Target;

use crate::probe::{Error, ErrorKind};
use crate::traceroute::WORKFLOW;
use crate::traceroute::{
    DEFAULT_MAX_UNDECODED_FRAMES, MAX_DURATION, MAX_PROBES, MAX_PROBES_PER_HOP, MAX_RATE,
};

pub use crate::probe::Transport as Strategy;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub target: Target,
    pub strategy: Strategy,
    pub address_family: Family,
    /// UDP base destination port or fixed TCP destination port. ICMP requires
    /// this to be absent.
    pub destination_port: Option<u16>,
    /// Optional non-zero UDP/TCP source port. `None` selects the ephemeral
    /// base the workflow already probes from.
    pub source_port: Option<u16>,
    pub first_hop: u8,
    pub max_hops: u8,
    pub probes_per_hop: u32,
    pub timeout: Duration,
    pub probes_per_second: Option<u32>,
    pub limits: Limits,
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if self.first_hop == 0 {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "first_hop",
                    value: 0,
                    reason: "must be within 1..=255".to_owned(),
                },
            ));
        }
        if self.max_hops < self.first_hop {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "max_hops",
                    value: u64::from(self.max_hops),
                    reason: format!("must be at least first_hop={}", self.first_hop),
                },
            ));
        }
        if !(1..=MAX_PROBES_PER_HOP).contains(&self.probes_per_hop) {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "probes_per_hop",
                    value: u64::from(self.probes_per_hop),
                    reason: format!("must be within 1..={MAX_PROBES_PER_HOP}"),
                },
            ));
        }
        if usize::try_from(self.probes_per_hop).unwrap_or(usize::MAX)
            > self.limits.max_evidence_frames
        {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "probes_per_hop",
                    value: u64::from(self.probes_per_hop),
                    reason: format!(
                        "cannot exceed max_evidence_frames={} because every probe may receive a response",
                        self.limits.max_evidence_frames
                    ),
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
        match (self.strategy, self.destination_port) {
            (Strategy::Udp | Strategy::Tcp, None) => {
                return Err(Error::new(
                    WORKFLOW,
                    ErrorKind::InvalidPort {
                        message: "UDP and TCP traceroute require a destination port".to_owned(),
                    },
                ));
            }
            (Strategy::Udp | Strategy::Tcp, Some(0)) => {
                return Err(Error::new(
                    WORKFLOW,
                    ErrorKind::InvalidPort {
                        message: "UDP and TCP traceroute require a non-zero destination port"
                            .to_owned(),
                    },
                ));
            }
            (Strategy::Icmp, Some(_)) => {
                return Err(Error::new(
                    WORKFLOW,
                    ErrorKind::InvalidPort {
                        message: "ICMP traceroute is portless".to_owned(),
                    },
                ));
            }
            _ => {}
        }
        if self.source_port == Some(0)
            || (self.strategy == Strategy::Icmp && self.source_port.is_some())
        {
            return Err(Error::new(WORKFLOW, ErrorKind::InvalidSourcePort));
        }
        Ok(())
    }

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "`validate` rejects `max_hops < first_hop`, so the u8 subtraction cannot \
                  underflow, and a u8 widened to usize leaves room for the increment"
    )]
    pub(in crate::traceroute) fn hop_count(&self) -> usize {
        usize::from(self.max_hops - self.first_hop) + 1
    }

    pub(in crate::traceroute) fn total_probe_count(&self) -> Result<usize, Error> {
        self.hop_count()
            .checked_mul(usize::try_from(self.probes_per_hop).unwrap_or(usize::MAX))
            .ok_or(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "probes",
                    value: u64::MAX,
                    reason: "probe-count arithmetic overflowed".to_owned(),
                },
            ))
    }
}
