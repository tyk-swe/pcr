// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_core::template::DEFAULT_MAX_TEMPLATE_PACKETS;
use packetcraftr_netio::deadline::MAX_WAIT;

use crate::execution::limits::{check_limits, check_rate, duration_violation};
use crate::target::Family;
use crate::target::Selection;

use super::Error;
use super::error::Probes;
use crate::probe::{ProbeEndpoint, Transport};
use crate::scan::{
    DEFAULT_MAX_PORTS, DEFAULT_MAX_UNDECODED_FRAMES, MAX_ATTEMPTS, MAX_IN_FLIGHT, MAX_PROBES,
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

/// A range whose `end` precedes its `start` selects nothing.
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
                return Err(Error::InvalidLimit {
                    field: "ports",
                    value: u64::try_from(ports.len())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                    reason: format!("exceeds max_ports={max_ports}"),
                });
            }
            ports.push(port);
        }
    }
    Ok(ports)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub max_in_flight: usize,
    pub targets: Selection,
    /// Source labels in declaration order, such as `inventory.txt:12` or
    /// `stdin:3`. Empty uses declaration ordinals; otherwise supply one label
    /// per included specification, each nonempty and at most 4096 bytes.
    pub target_sources: Vec<String>,
    /// Probed on every scanned target, in order; TCP, UDP, and SCTP endpoints
    /// may share a port and never merge. ICMP echo and IP-protocol scans are
    /// portless and stand alone. Empty only for discovery-only requests.
    pub endpoints: Vec<ProbeEndpoint>,
    /// The segment sent to each TCP scan endpoint; discovery, UDP, SCTP, ICMP,
    /// and IP-protocol probes ignore it.
    pub tcp_scan: super::TcpScan,
    /// The chunk sent to each SCTP scan endpoint; discovery SCTP probes always
    /// send `INIT`.
    pub sctp_scan: super::SctpScan,
    pub discovery: super::discovery::Options,
    /// Exact bytes appended to each UDP probe; empty preserves an empty datagram.
    pub udp_payload: bytes::Bytes,
    pub udp_profiles: std::collections::BTreeMap<u16, std::sync::Arc<super::profile::UdpProfile>>,
    pub address_family: Family,
    pub attempts: u32,
    pub adaptive: Option<super::Adaptive>,
    pub timeout: Duration,
    pub probes_per_second: Option<u32>,
    pub limits: Limits,
    pub route: crate::route::Options,
    pub collection: crate::exchange::Collection,
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if self.max_in_flight == 0 || self.max_in_flight > MAX_IN_FLIGHT {
            return Err(Error::InvalidLimit {
                field: "max_in_flight",
                value: self.max_in_flight as u64,
                reason: format!("must be within 1..={MAX_IN_FLIGHT}"),
            });
        }
        self.targets.validate().map_err(Error::TargetSelection)?;
        if !self.target_sources.is_empty()
            && self.target_sources.len() != self.targets.include.len()
        {
            return Err(Error::InvalidLimit {
                field: "target_sources",
                value: self.target_sources.len() as u64,
                reason: format!(
                    "supply one source label per included declaration ({}), or none",
                    self.targets.include.len()
                ),
            });
        }
        for (index, source) in self.target_sources.iter().enumerate() {
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
        if self.udp_profiles.len() > packetcraftr_core::document::udp_profiles::MAX_PROFILE_PORTS
            || (!self.udp_profiles.is_empty() && !self.probes(Transport::Udp))
        {
            return Err(Error::InvalidLimit {
                field: "udp_profiles",
                value: self.udp_profiles.len() as u64,
                reason: "profiles require UDP and at most 4096 port mappings".to_owned(),
            });
        }
        let mut seen_profiles = std::collections::HashSet::new();
        let mut profile_bytes = 0usize;
        for profile in self.udp_profiles.values() {
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
        if self.udp_payload.len() > super::MAX_UDP_PAYLOAD_BYTES
            || (!self.udp_payload.is_empty() && !self.probes(Transport::Udp))
        {
            return Err(Error::InvalidLimit {
                field: "udp_payload_bytes",
                value: u64::try_from(self.udp_payload.len()).unwrap_or(u64::MAX),
                reason: format!(
                    "UDP scans accept at most {} payload bytes; TCP and ICMP require an empty payload",
                    super::MAX_UDP_PAYLOAD_BYTES
                ),
            });
        }
        if !(1..=MAX_ATTEMPTS).contains(&self.attempts) {
            return Err(Error::InvalidLimit {
                field: "attempts",
                value: u64::from(self.attempts),
                reason: format!("must be within 1..={MAX_ATTEMPTS}"),
            });
        }
        if duration_violation(self.timeout, MAX_WAIT) {
            return Err(Error::InvalidTimeout {
                value: self.timeout,
                maximum: MAX_WAIT,
            });
        }
        if let Some(adaptive) = &self.adaptive {
            adaptive.validate(self)?;
        }
        check_rate(&Probes, "probes_per_second", self.probes_per_second)?;
        self.discovery
            .validate(&self.route, &self.limits, self.address_family)?;
        self.validate_endpoints()?;
        self.validate_tcp_scan()?;
        self.validate_sctp_scan()
    }

    /// Whether any scan endpoint or discovery probe uses `transport`.
    pub fn probes(&self, transport: Transport) -> bool {
        let discovery = if self.discovery.runs() {
            self.discovery.probes.as_slice()
        } else {
            &[]
        };
        self.endpoints
            .iter()
            .chain(discovery)
            .any(|endpoint| endpoint.transport() == transport)
    }

    fn validate_tcp_scan(&self) -> Result<(), Error> {
        self.tcp_scan.validate()?;
        if !self.tcp_scan.is_syn()
            && !self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.transport() == Transport::Tcp)
        {
            return Err(Error::InvalidLimit {
                field: "tcp_scan",
                value: u64::from(self.tcp_scan.flags()),
                reason: format!(
                    "{} scans require at least one TCP scan endpoint",
                    self.tcp_scan.as_str()
                ),
            });
        }
        Ok(())
    }

    fn validate_sctp_scan(&self) -> Result<(), Error> {
        if !self.sctp_scan.is_init()
            && !self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.transport() == Transport::Sctp)
        {
            return Err(Error::InvalidLimit {
                field: "sctp_scan",
                value: u64::from(self.sctp_scan.chunk_type()),
                reason: format!(
                    "{} scans require at least one SCTP scan endpoint",
                    self.sctp_scan.as_str()
                ),
            });
        }
        Ok(())
    }

    fn validate_endpoints(&self) -> Result<(), Error> {
        let invalid = |message: String| Err(Error::InvalidPort { message });
        if self.discovery.mode == super::discovery::Mode::Only {
            if self.endpoints.is_empty() {
                return Ok(());
            }
            return Err(Error::InvalidDiscovery {
                message: "discovery-only requests probe no scan endpoint".to_owned(),
            });
        }
        if self.endpoints.is_empty() {
            return invalid(
                "TCP and UDP scans require at least one destination port; SCTP and IP-protocol scans also require at least one destination endpoint"
                    .to_owned(),
            );
        }
        if let Some(endpoint) = self.endpoints.iter().find(|endpoint| {
            matches!(
                endpoint,
                ProbeEndpoint::TcpAck { .. }
                    | ProbeEndpoint::IcmpTimestamp
                    | ProbeEndpoint::IcmpNetmask
            )
        }) {
            return Err(Error::InvalidDiscovery {
                message: format!("{endpoint} is a host-discovery probe, not a scan endpoint"),
            });
        }
        if self.endpoints.contains(&ProbeEndpoint::Sctp { port: 0 }) {
            return invalid("SCTP scans require a non-zero destination port".to_owned());
        }
        // Discovery may pair ICMP echo with port probes; only the scan's
        // portless ICMP endpoint stands alone.
        if self.endpoints.contains(&ProbeEndpoint::Icmp) && self.endpoints.len() > 1 {
            return invalid(
                "ICMP scans are portless and do not accept destination ports".to_owned(),
            );
        }
        let has_ip_protocol = self
            .endpoints
            .iter()
            .any(|endpoint| matches!(endpoint, ProbeEndpoint::Ip { .. }));
        if has_ip_protocol
            && self
                .endpoints
                .iter()
                .any(|endpoint| !matches!(endpoint, ProbeEndpoint::Ip { .. }))
        {
            return invalid(
                "IP-protocol scans are portless and cannot combine with port or ICMP endpoints"
                    .to_owned(),
            );
        }
        if self.endpoints.len() > self.limits.max_ports {
            return Err(Error::InvalidLimit {
                field: "ports",
                value: u64::try_from(self.endpoints.len()).unwrap_or(u64::MAX),
                reason: format!("exceeds max_ports={}", self.limits.max_ports),
            });
        }
        let mut seen = HashSet::with_capacity(self.endpoints.len());
        for endpoint in &self.endpoints {
            if !seen.insert(*endpoint) {
                return invalid(format!("endpoint {endpoint} is listed more than once"));
            }
        }
        // Discovery probes share the port budget with the scan's endpoints:
        // the distinct set across both stages counts once toward max_ports.
        if self.discovery.runs() && !self.discovery.probes.is_empty() {
            let distinct = self
                .endpoints
                .iter()
                .chain(&self.discovery.probes)
                .collect::<HashSet<_>>();
            if distinct.len() > self.limits.max_ports {
                return Err(Error::InvalidLimit {
                    field: "ports",
                    value: u64::try_from(distinct.len()).unwrap_or(u64::MAX),
                    reason: format!("exceeds max_ports={}", self.limits.max_ports),
                });
            }
        }
        Ok(())
    }

    /// The validated endpoints every target is probed on.
    pub fn planned_endpoints(&self) -> Result<&[ProbeEndpoint], Error> {
        self.validate()?;
        Ok(&self.endpoints)
    }

    pub(crate) fn duplicate_diagnostic(
        &self,
        index: u32,
    ) -> packetcraftr_core::diagnostic::Diagnostic {
        let source = self
            .target_sources
            .get(index as usize)
            .map(|source| format!(" ({source})"))
            .unwrap_or_default();
        packetcraftr_core::diagnostic::Diagnostic::warning(
            "scan.duplicate_declaration",
            format!(
                "target declaration {}{source} duplicates an earlier declaration and was coalesced",
                index + 1
            ),
        )
    }
}
