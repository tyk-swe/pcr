// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod host;

use std::collections::HashSet;

pub use host::{
    Basis, Evidence, Host, Link, Neighbor, NeighborOutcome, NextHop, Reason, ReasonKind, Scan,
    State,
};
pub(super) use host::{Composer, Observation, check_probes, scanned};

use super::Error;
use crate::probe;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Mode {
    #[default]
    Omitted,
    Skipped,
    Before,
    Only,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Unresponsive {
    #[default]
    Skip,
    Scan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    probes: Vec<probe::Endpoint>,
    neighbor: bool,
}

impl Plan {
    pub(super) fn new(probes: Vec<probe::Endpoint>, neighbor: bool) -> Result<Self, Error> {
        if probes.is_empty() && !neighbor {
            return Err(Error::InvalidDiscovery {
                message: "discovery needs at least one probe".to_owned(),
            });
        }
        if probes.len() > super::MAX_PROBES {
            return Err(Error::InvalidLimit {
                field: "discovery_probes",
                value: u64::try_from(probes.len()).unwrap_or(u64::MAX),
                reason: format!("exceeds max_probes={}", super::MAX_PROBES),
            });
        }
        Ok(Self { probes, neighbor })
    }

    pub fn probes(&self) -> &[probe::Endpoint] {
        &self.probes
    }

    pub const fn neighbor(&self) -> bool {
        self.neighbor
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Options {
    #[default]
    Omitted,
    Skipped,
    Before {
        plan: Plan,
        unresponsive: Unresponsive,
    },
    Only(Plan),
}

impl Options {
    #[must_use]
    pub const fn runs(&self) -> bool {
        matches!(self, Self::Before { .. } | Self::Only(_))
    }

    pub const fn mode(&self) -> Mode {
        match self {
            Self::Omitted => Mode::Omitted,
            Self::Skipped => Mode::Skipped,
            Self::Before { .. } => Mode::Before,
            Self::Only(_) => Mode::Only,
        }
    }

    pub fn probes(&self) -> &[probe::Endpoint] {
        self.plan().map_or(&[], Plan::probes)
    }

    pub const fn neighbor(&self) -> bool {
        match self {
            Self::Before { plan, .. } | Self::Only(plan) => plan.neighbor,
            Self::Omitted | Self::Skipped => false,
        }
    }

    pub const fn unresponsive(&self) -> Unresponsive {
        match self {
            Self::Before { unresponsive, .. } => *unresponsive,
            Self::Omitted | Self::Skipped | Self::Only(_) => Unresponsive::Skip,
        }
    }

    const fn plan(&self) -> Option<&Plan> {
        match self {
            Self::Before { plan, .. } | Self::Only(plan) => Some(plan),
            Self::Omitted | Self::Skipped => None,
        }
    }

    pub(super) fn validate(
        &self,
        route: &crate::route::Options,
        limits: &super::Limits,
        family: crate::target::Family,
    ) -> Result<(), Error> {
        if !self.runs() {
            return Ok(());
        }
        if self.probes().contains(&probe::Endpoint::Sctp { port: 0 }) {
            return Err(Error::InvalidPort {
                message: "SCTP discovery probes require a non-zero destination port".to_owned(),
            });
        }
        if family == crate::target::Family::Ipv6
            && self.probes().iter().any(|probe| {
                matches!(
                    probe,
                    probe::Endpoint::IcmpTimestamp | probe::Endpoint::IcmpNetmask
                )
            })
        {
            return Err(Error::InvalidDiscovery {
                message:
                    "ICMP timestamp and netmask discovery probes are IPv4-only and cannot be used with IPv6 targets"
                        .to_owned(),
            });
        }
        if self.probes().len() > limits.max_ports {
            return Err(Error::InvalidLimit {
                field: "discovery_probes",
                value: u64::try_from(self.probes().len()).unwrap_or(u64::MAX),
                reason: format!("exceeds max_ports={}", limits.max_ports),
            });
        }
        let mut seen = HashSet::with_capacity(self.probes().len());
        if let Some(duplicate) = self.probes().iter().find(|probe| !seen.insert(**probe)) {
            return Err(Error::InvalidDiscovery {
                message: format!("discovery probe {duplicate} is listed more than once"),
            });
        }
        if self.neighbor() && route.link_mode == packetcraftr_netio::link::Mode::Layer3 {
            return Err(Error::InvalidDiscovery {
                message: "neighbor discovery needs a link-layer route".to_owned(),
            });
        }
        Ok(())
    }
}
