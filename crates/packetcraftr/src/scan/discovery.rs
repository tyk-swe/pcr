// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod host;
#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::time::Duration;

pub use host::{
    Basis, Evidence, Host, Link, Neighbor, NeighborOutcome, NextHop, Reason, ReasonKind, Scan,
    State,
};
pub(super) use host::{Composer, Observation, check_probes};

use super::Error;
use crate::probe::ProbeEndpoint;

/// Whether and how a scan request discovers hosts. Discovery never runs
/// unless selected, so a scan sends no probe its request did not name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Mode {
    /// The request did not ask for discovery: every host is scanned, and its
    /// record says it was not discovered.
    #[default]
    Omitted,
    /// Discovery was explicitly skipped: every host is scanned without any
    /// claim that it is reachable.
    Skipped,
    /// Discovery runs first, and its result decides which hosts are scanned.
    Before,
    /// Discovery runs alone and no port is probed.
    Only,
}

/// What the scan stage does with hosts that did not answer discovery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Unresponsive {
    /// Leave them unscanned; their records say so.
    #[default]
    Skip,
    /// Scan them like hosts that answered.
    Scan,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub mode: Mode,
    /// The probes each target receives, in order, after neighbor discovery.
    /// Unlike scan endpoints, ICMP echo combines with TCP and UDP ports.
    pub probes: Vec<ProbeEndpoint>,
    /// Resolve each target's link address with ARP or NDP first. Routed
    /// targets resolve their next hop instead, which is never host evidence.
    pub neighbor: bool,
    pub unresponsive: Unresponsive,
}

impl Options {
    /// Whether this request runs a discovery stage.
    #[must_use]
    pub const fn runs(&self) -> bool {
        matches!(self.mode, Mode::Before | Mode::Only)
    }

    pub(super) fn validate(
        &self,
        timeout: Duration,
        route: &crate::route::Options,
        limits: &super::Limits,
    ) -> Result<(), Error> {
        let invalid = |message: &str| {
            Err(Error::InvalidDiscovery {
                message: message.to_owned(),
            })
        };
        if !self.runs() {
            if !self.probes.is_empty() || self.neighbor {
                return invalid("discovery probes need a discovery stage that runs");
            }
            if self.unresponsive != Unresponsive::Skip {
                return invalid("unresponsive hosts can be scanned only after discovery");
            }
            return Ok(());
        }
        if self.mode == Mode::Only && self.unresponsive != Unresponsive::Skip {
            return invalid("discovery-only requests scan no host");
        }
        if self.probes.is_empty() && !self.neighbor {
            return invalid("discovery needs at least one probe");
        }
        if self.probes.len() > limits.max_ports {
            return Err(Error::InvalidLimit {
                field: "discovery_probes",
                value: u64::try_from(self.probes.len()).unwrap_or(u64::MAX),
                reason: format!("exceeds max_ports={}", limits.max_ports),
            });
        }
        let mut seen = HashSet::with_capacity(self.probes.len());
        if let Some(duplicate) = self.probes.iter().find(|probe| !seen.insert(**probe)) {
            return Err(Error::InvalidDiscovery {
                message: format!("discovery probe {duplicate} is listed more than once"),
            });
        }
        if self.neighbor {
            if route.link_mode == packetcraftr_netio::link::Mode::Layer3 {
                return invalid("neighbor discovery needs a link-layer route");
            }
            // Each attempt is one resolver request bounded like a probe.
            crate::neighbor::Options::default()
                .single_attempt(
                    timeout,
                    limits.max_evidence_frames,
                    limits.max_evidence_bytes,
                )
                .validate()
                .map_err(|source| Error::InvalidDiscovery {
                    message: format!(
                        "neighbor discovery cannot use the scan timeout and evidence limits: {source}"
                    ),
                })?;
        }
        Ok(())
    }
}
