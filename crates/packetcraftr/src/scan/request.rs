// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(test)]
mod tests;

use packetcraftr_core::diagnostic::Severity;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_core::template::DEFAULT_MAX_TEMPLATE_PACKETS;
use packetcraftr_netio::deadline::MAX_WAIT;

use crate::deadline::duration_violation;
use crate::engine::execution::limits::check_rate;
use crate::evidence::limits::check_limits;
use crate::target::{Family, Selection};

use super::Error;
use crate::probe::{self, Transport};
use crate::scan::{
    DEFAULT_MAX_PORTS, DEFAULT_MAX_UNDECODED_FRAMES, MAX_IN_FLIGHT, MAX_PROBE_ATTEMPTS, MAX_PROBES,
};

crate::evidence::limits_serde!(
    before: {
        max_prepared_bytes: usize,
        max_targets: usize,
        max_ports: usize,
        max_probes: usize,
        max_duration: std::time::Duration,
    },
    after: {}
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "limits_serde::Limits", into = "limits_serde::Limits")]
pub struct Limits {
    pub max_prepared_bytes: usize,
    pub max_targets: usize,
    pub max_ports: usize,
    pub max_probes: usize,
    pub max_duration: Duration,
    pub evidence: crate::evidence::Limits,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_prepared_bytes: 64 * 1024 * 1024,
            max_targets: 1024,
            max_ports: DEFAULT_MAX_PORTS,
            max_probes: DEFAULT_MAX_TEMPLATE_PACKETS,
            max_duration: MAX_WAIT,
            evidence: crate::evidence::Limits {
                max_undecoded: DEFAULT_MAX_UNDECODED_FRAMES,
                ..crate::evidence::Limits::default()
            },
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        check_limits(
            &[
                (
                    "max_prepared_bytes",
                    self.max_prepared_bytes,
                    super::MAX_PREPARED_BYTES,
                ),
                ("max_targets", self.max_targets, super::MAX_PROBES),
                ("max_ports", self.max_ports, usize::from(u16::MAX) + 1),
                ("max_probes", self.max_probes, MAX_PROBES),
            ],
            &[],
            |field, value, reason| Error::InvalidLimit {
                field,
                value,
                reason,
            },
        )?;
        self.evidence
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
pub struct Targets {
    pub selection: Selection,
    /// One source label per included declaration, or none for declaration ordinals.
    pub sources: Vec<String>,
    pub family: Family,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Udp {
    pub payload: bytes::Bytes,
    pub profiles: std::collections::BTreeMap<u16, std::sync::Arc<super::profile::UdpProfile>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub max_in_flight: usize,
    pub attempts: u32,
    pub adaptive: Option<super::Adaptive>,
    pub timeout: Duration,
    pub probes_per_second: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct Base {
    pub selection: super::selection::Prepared,
    pub targets: Targets,
    pub udp: Udp,
    pub schedule: Schedule,
    pub limits: Limits,
}

#[derive(Clone, Debug)]
pub struct Request {
    selection: super::selection::Prepared,
    targets: Targets,
    udp: Udp,
    schedule: Schedule,
    limits: Limits,
    route: crate::route::Options,
    collection: crate::exchange::Collection,
}

impl Request {
    pub fn new(
        base: Base,
        route: crate::route::Options,
        collection: crate::exchange::Collection,
    ) -> Result<Self, Error> {
        let Base {
            selection,
            targets,
            udp,
            schedule,
            limits,
        } = base;
        let request = Self {
            selection,
            targets,
            udp,
            schedule,
            limits,
            route,
            collection,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn with_workflow(
        self,
        route: crate::route::Options,
        collection: crate::exchange::Collection,
    ) -> Result<Self, Error> {
        Self::new(
            Base {
                selection: self.selection,
                targets: self.targets,
                udp: self.udp,
                schedule: self.schedule,
                limits: self.limits,
            },
            route,
            collection,
        )
    }

    pub fn endpoints(&self) -> &[probe::Endpoint] {
        self.selection.endpoints()
    }

    pub fn discovery(&self) -> &super::discovery::Options {
        self.selection.discovery()
    }

    pub fn selection_excluded_endpoints(&self) -> usize {
        self.selection.excluded_endpoints()
    }

    pub fn discovery_excluded(&self) -> usize {
        self.selection.discovery_excluded()
    }

    pub fn targets(&self) -> &Selection {
        &self.targets.selection
    }

    pub fn target_sources(&self) -> &[String] {
        &self.targets.sources
    }

    pub const fn address_family(&self) -> Family {
        self.targets.family
    }

    pub const fn tcp_scan(&self) -> super::TcpScan {
        self.selection.tcp_scan()
    }

    pub const fn sctp_scan(&self) -> super::SctpScan {
        self.selection.sctp_scan()
    }

    pub fn udp_payload(&self) -> &bytes::Bytes {
        &self.udp.payload
    }

    pub fn udp_profiles(
        &self,
    ) -> &std::collections::BTreeMap<u16, std::sync::Arc<super::profile::UdpProfile>> {
        &self.udp.profiles
    }

    pub const fn schedule(&self) -> &Schedule {
        &self.schedule
    }

    pub const fn limits(&self) -> &Limits {
        &self.limits
    }

    pub const fn route(&self) -> &crate::route::Options {
        &self.route
    }

    pub const fn collection(&self) -> &crate::exchange::Collection {
        &self.collection
    }

    pub(super) fn has_ip_probes(&self) -> bool {
        self.endpoints()
            .iter()
            .any(|endpoint| matches!(endpoint, crate::probe::Endpoint::Ip { .. }))
            || self
                .discovery()
                .probes()
                .iter()
                .any(|endpoint| matches!(endpoint, crate::probe::Endpoint::Ip { .. }))
    }

    fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if self.endpoints().is_empty() && self.discovery().mode() != super::discovery::Mode::Only {
            return Err(Error::InvalidPort {
                message: "TCP and UDP scans require at least one destination port; SCTP and IP-protocol scans also require at least one destination endpoint".to_owned(),
            });
        }

        let distinct = self
            .endpoints()
            .iter()
            .chain(self.discovery().probes())
            .collect::<std::collections::HashSet<_>>();
        if distinct.len() > self.limits.max_ports {
            return Err(Error::InvalidLimit {
                field: "ports",
                value: u64::try_from(distinct.len()).unwrap_or(u64::MAX),
                reason: format!("exceeds max_ports={}", self.limits.max_ports),
            });
        }
        self.tcp_scan().validate()?;
        if self.schedule.max_in_flight == 0 || self.schedule.max_in_flight > MAX_IN_FLIGHT {
            return Err(Error::InvalidLimit {
                field: "max_in_flight",
                value: self.schedule.max_in_flight as u64,
                reason: format!("must be within 1..={MAX_IN_FLIGHT}"),
            });
        }
        self.targets
            .selection
            .validate()
            .map_err(Error::TargetSelection)?;
        if !self.targets.sources.is_empty()
            && self.targets.sources.len() != self.targets.selection.include.len()
        {
            return Err(Error::InvalidLimit {
                field: "target_sources",
                value: self.targets.sources.len() as u64,
                reason: format!(
                    "supply one source label per included declaration ({}), or none",
                    self.targets.selection.include.len()
                ),
            });
        }
        for (index, source) in self.targets.sources.iter().enumerate() {
            if source.is_empty() || source.len() > 4096 {
                return Err(Error::InvalidLimit {
                    field: "target_sources",
                    value: source.len() as u64,
                    reason: format!(
                        "source label for target declaration {} must contain 1..=4096 bytes",
                        index + 1
                    ),
                });
            }
        }
        if self.udp.profiles.len() > packetcraftr_core::document::udp_profiles::MAX_PROFILE_PORTS
            || (!self.udp.profiles.is_empty() && !self.probes(Transport::Udp))
        {
            return Err(Error::InvalidLimit {
                field: "udp_profiles",
                value: self.udp.profiles.len() as u64,
                reason: "profiles require UDP and at most 4096 port mappings".to_owned(),
            });
        }
        let mut seen_profiles = std::collections::HashSet::new();
        let mut profile_bytes = 0usize;
        for profile in self.udp.profiles.values() {
            if seen_profiles.insert(std::sync::Arc::as_ptr(profile)) {
                profile_bytes = profile_bytes.saturating_add(profile.storage_bytes());
            }
        }
        if profile_bytes > packetcraftr_core::document::udp_profiles::MAX_PROFILE_BYTES {
            return Err(Error::InvalidLimit {
                field: "udp_profile_bytes",
                value: profile_bytes as u64,
                reason: "compiled profiles exceed 1 MiB".to_owned(),
            });
        }
        if self.udp.payload.len() > super::MAX_UDP_PAYLOAD_BYTES
            || (!self.udp.payload.is_empty() && !self.probes(Transport::Udp))
        {
            return Err(Error::InvalidLimit {
                field: "udp_payload_bytes",
                value: u64::try_from(self.udp.payload.len()).unwrap_or(u64::MAX),
                reason: format!(
                    "UDP scans accept at most {} payload bytes; TCP and ICMP require an empty payload",
                    super::MAX_UDP_PAYLOAD_BYTES
                ),
            });
        }
        if !(1..=MAX_PROBE_ATTEMPTS).contains(&self.schedule.attempts) {
            return Err(Error::InvalidLimit {
                field: "attempts",
                value: u64::from(self.schedule.attempts),
                reason: format!("must be within 1..={MAX_PROBE_ATTEMPTS}"),
            });
        }
        if duration_violation(self.schedule.timeout, MAX_WAIT) {
            return Err(Error::InvalidTimeout {
                value: self.schedule.timeout,
                maximum: MAX_WAIT,
            });
        }
        if let Some(adaptive) = self.schedule.adaptive {
            adaptive.validate(self)?;
        }
        check_rate::<Error>("probes_per_second", self.schedule.probes_per_second)?;
        self.discovery()
            .validate(&self.route, &self.limits, self.targets.family)?;
        self.collection
            .validate()
            .map_err(|source| Error::InvalidLimit {
                field: "collection",
                value: 0,
                reason: source.to_string(),
            })
    }

    pub fn probes(&self, transport: Transport) -> bool {
        self.endpoints()
            .iter()
            .chain(self.discovery().probes())
            .any(|endpoint| endpoint.transport() == transport)
    }

    pub(crate) fn duplicate_diagnostic(
        &self,
        index: u32,
    ) -> packetcraftr_core::diagnostic::Diagnostic {
        let source = self
            .targets
            .sources
            .get(index as usize)
            .map(|source| format!(" ({source})"))
            .unwrap_or_default();
        packetcraftr_core::diagnostic::Diagnostic::new(
            Severity::Warning,
            "scan.duplicate_declaration",
            format!(
                "target declaration {}{source} duplicates an earlier declaration and was coalesced",
                index + 1
            ),
        )
    }
}
