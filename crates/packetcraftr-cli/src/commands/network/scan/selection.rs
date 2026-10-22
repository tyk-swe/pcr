// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::probe::{self, Transport};
use packetcraftr::scan::{Selected, discovery};
use packetcraftr_core::error::{Classified, Kind};

use super::arguments;
use crate::errors::CliError;

/// The requested transports in first-seen order. ICMP echo and IP-protocol
/// inventory are portless and cannot share a plan with port endpoints.
pub(super) fn transports(requested: &[arguments::Transport]) -> Result<Vec<Transport>, CliError> {
    let mut transports: Vec<Transport> = Vec::with_capacity(requested.len());
    for transport in requested {
        let transport = Transport::from(*transport);
        if !transports.contains(&transport) {
            transports.push(transport);
        }
    }
    if transports.len() > 1 && transports.contains(&Transport::Icmp) {
        return Err(CliError::new(
            Kind::Usage,
            "--transport icmp is portless and cannot be combined with tcp or udp (or sctp/ip)",
        ));
    }
    if transports.len() > 1 && transports.contains(&Transport::Ip) {
        return Err(CliError::new(
            Kind::Usage,
            "--transport ip is portless and cannot be combined with tcp or udp (or sctp/icmp)",
        ));
    }
    Ok(transports)
}

/// Endpoint inputs shared by live scans and `--list` validation.
#[derive(Clone, Debug)]
pub(super) struct EndpointRequest {
    pub(super) transports: Vec<Transport>,
    pub(super) ports: Vec<arguments::PortTerm>,
    pub(super) exclude_ports: Vec<arguments::PortTerm>,
    pub(super) ip_protocols: Vec<arguments::IpProtocolTerm>,
    pub(super) exclude_ip_protocols: Vec<arguments::IpProtocolTerm>,
    pub(super) max_ports: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EndpointUse {
    Scan,
    Listing,
}

impl EndpointRequest {
    /// Select the scan endpoints after applying the same transport rules for
    /// every caller. Live scans require an explicit selection here; `--list`
    /// uses [`Self::select_if_requested`] so an omitted plan section remains
    /// omitted.
    pub(super) fn select(self) -> Result<Selected, CliError> {
        self.validate(EndpointUse::Scan)?;
        self.expand()
    }

    /// Validate the endpoint shape, but leave an omitted port/protocol
    /// selection absent for `--list`.
    pub(super) fn select_if_requested(self) -> Result<Option<Selected>, CliError> {
        self.validate(EndpointUse::Listing)?;
        if !self.configured() {
            return Ok(None);
        }
        self.expand().map(Some)
    }

    /// Discovery consumes exclusions that apply only to its port probes.
    /// Keep scan-applicable terms, plus terms discovery did not consume, so
    /// scan endpoint validation neither rejects nor miscounts them.
    pub(super) fn retain_scan_exclusions(&mut self, discovery_transports: &[Transport]) {
        self.exclude_ports.retain(|term| {
            let applies_to_scan = term.0.transport.map_or_else(
                || {
                    self.transports.iter().any(|transport| {
                        matches!(transport, Transport::Tcp | Transport::Udp | Transport::Sctp)
                    })
                },
                |transport| self.transports.contains(&transport),
            );
            applies_to_scan
                || !discovery_transports.iter().any(|transport| {
                    term.0
                        .transport
                        .is_none_or(|excluded| excluded == *transport)
                })
        });
    }

    pub(super) const fn has_includes(&self) -> bool {
        !self.ports.is_empty() || !self.ip_protocols.is_empty()
    }

    pub(super) fn clear_ip_exclusions(&mut self) {
        self.exclude_ip_protocols.clear();
    }

    fn configured(&self) -> bool {
        if self.transports == [Transport::Ip] {
            !self.ip_protocols.is_empty() || !self.exclude_ip_protocols.is_empty()
        } else {
            !self.ports.is_empty() || !self.exclude_ports.is_empty()
        }
    }

    fn validate(&self, endpoint_use: EndpointUse) -> Result<(), CliError> {
        if self.transports == [Transport::Icmp] {
            // The historical list path reports incompatible IP-protocol flags
            // before rejecting port terms on a portless ICMP scan. A live scan
            // has always reported the port error first.
            if endpoint_use == EndpointUse::Listing
                && (!self.ip_protocols.is_empty() || !self.exclude_ip_protocols.is_empty())
            {
                return Err(CliError::new(
                    Kind::Usage,
                    "--ip-protocols and --exclude-ip-protocols require --transport ip",
                ));
            }
            if !self.ports.is_empty() || !self.exclude_ports.is_empty() {
                return Err(CliError::new(
                    Kind::Usage,
                    "--ports and --exclude-ports do not apply to portless ICMP echo scans",
                ));
            }
            if !self.ip_protocols.is_empty() || !self.exclude_ip_protocols.is_empty() {
                return Err(CliError::new(
                    Kind::Usage,
                    "--ip-protocols and --exclude-ip-protocols require --transport ip",
                ));
            }
            return Ok(());
        }
        if self.transports == [Transport::Ip] {
            if !self.ports.is_empty() || !self.exclude_ports.is_empty() {
                return Err(CliError::new(
                    Kind::Usage,
                    "--ports and --exclude-ports do not apply to portless IP-protocol scans; use --ip-protocols",
                ));
            }
            return Ok(());
        }
        if !self.ip_protocols.is_empty() || !self.exclude_ip_protocols.is_empty() {
            return Err(CliError::new(
                Kind::Usage,
                "--ip-protocols and --exclude-ip-protocols require --transport ip",
            ));
        }
        Ok(())
    }

    fn expand(self) -> Result<Selected, CliError> {
        if self.transports == [Transport::Icmp] {
            return Ok(Selected {
                endpoints: vec![probe::Endpoint::Icmp],
                excluded: 0,
            });
        }
        if self.transports == [Transport::Ip] {
            return packetcraftr::scan::select_ip_protocols(
                &packetcraftr::scan::IpProtocolSelection {
                    include: self.ip_protocols.into_iter().map(|term| term.0).collect(),
                    exclude: self
                        .exclude_ip_protocols
                        .into_iter()
                        .map(|term| term.0)
                        .collect(),
                },
                self.max_ports,
            )
            .map_err(CliError::classified);
        }
        packetcraftr::scan::select_endpoints(
            &packetcraftr::scan::PortSelection {
                transports: self.transports,
                include: self.ports.into_iter().map(|term| term.0).collect(),
                exclude: self.exclude_ports.into_iter().map(|term| term.0).collect(),
            },
            packetcraftr::scan::catalog::bundled(),
            self.max_ports,
        )
        .map_err(CliError::classified)
    }
}

/// Discovery preparation inputs. The resulting effective probe endpoints are
/// kept beside the port transports they were derived from so callers do not
/// need to inspect probe flags again when filtering scan exclusions.
#[derive(Clone, Debug)]
pub(super) struct DiscoveryRequest {
    pub(super) mode: Option<arguments::Discovery>,
    pub(super) probes: Vec<arguments::DiscoveryProbe>,
    pub(super) ports: Vec<arguments::PortTerm>,
    pub(super) exclude_ports: Vec<arguments::PortTerm>,
    pub(super) ip_protocols: Vec<arguments::IpProtocolTerm>,
    pub(super) exclude_ip_protocols: Vec<arguments::IpProtocolTerm>,
    pub(super) unresponsive: Option<arguments::UnresponsiveHosts>,
    pub(super) max_ports: usize,
}

pub(super) struct PreparedDiscovery {
    pub(super) options: discovery::Options,
    pub(super) excluded: usize,
    pub(super) port_transports: Vec<Transport>,
}

impl DiscoveryRequest {
    /// The discovery stage the flags select, with the endpoints --exclude-ports
    /// and --exclude-ip-protocols removed from it. Port probes take
    /// --discovery-ports through the scan's catalog and --exclude-ports; IP
    /// protocol probes take --discovery-ip-protocols and
    /// --exclude-ip-protocols; ICMP echo is the default probe.
    pub(super) fn prepare(self) -> Result<PreparedDiscovery, CliError> {
        let Self {
            mode,
            probes,
            ports,
            exclude_ports,
            ip_protocols,
            exclude_ip_protocols,
            unresponsive,
            max_ports,
        } = self;
        let Some(mode) = mode else {
            return Ok(PreparedDiscovery {
                options: discovery::Options::default(),
                excluded: 0,
                port_transports: Vec::new(),
            });
        };
        let mut options = discovery::Options {
            mode: mode.into(),
            unresponsive: unresponsive.map_or_else(Default::default, Into::into),
            ..discovery::Options::default()
        };
        let probes = if probes.is_empty() && options.runs() {
            vec![arguments::DiscoveryProbe::Icmp]
        } else {
            probes
        };
        let mut portless_icmp = Vec::new();
        let mut port_transports = Vec::new();
        let mut tcp_modes = Vec::new();
        let mut wants_ip_protocols = false;
        for probe in &probes {
            match probe {
                arguments::DiscoveryProbe::Neighbor => {
                    options.neighbor = true;
                }
                arguments::DiscoveryProbe::Icmp => {
                    if !portless_icmp.contains(&probe::Endpoint::Icmp) {
                        portless_icmp.push(probe::Endpoint::Icmp);
                    }
                }
                arguments::DiscoveryProbe::IcmpTimestamp => {
                    if !portless_icmp.contains(&probe::Endpoint::IcmpTimestamp) {
                        portless_icmp.push(probe::Endpoint::IcmpTimestamp);
                    }
                }
                arguments::DiscoveryProbe::IcmpNetmask => {
                    if !portless_icmp.contains(&probe::Endpoint::IcmpNetmask) {
                        portless_icmp.push(probe::Endpoint::IcmpNetmask);
                    }
                }
                arguments::DiscoveryProbe::Tcp => {
                    if !port_transports.contains(&Transport::Tcp) {
                        port_transports.push(Transport::Tcp);
                    }
                    if !tcp_modes.contains(&false) {
                        tcp_modes.push(false);
                    }
                }
                arguments::DiscoveryProbe::TcpAck => {
                    if !port_transports.contains(&Transport::Tcp) {
                        port_transports.push(Transport::Tcp);
                    }
                    if !tcp_modes.contains(&true) {
                        tcp_modes.push(true);
                    }
                }
                arguments::DiscoveryProbe::Udp => {
                    if !port_transports.contains(&Transport::Udp) {
                        port_transports.push(Transport::Udp);
                    }
                }
                arguments::DiscoveryProbe::Sctp => {
                    if !port_transports.contains(&Transport::Sctp) {
                        port_transports.push(Transport::Sctp);
                    }
                }
                arguments::DiscoveryProbe::Ip => {
                    wants_ip_protocols = true;
                }
            }
        }
        // Portless ICMP probes lead in first-seen order; port probes follow in
        // term order, then IP-protocol probes.
        options.probes.extend(portless_icmp);
        let mut excluded_total = 0usize;
        if port_transports.is_empty() {
            if !ports.is_empty() {
                return Err(CliError::new(
                    Kind::Usage,
                    "--discovery-ports needs tcp or udp among --discovery-probes (or tcp-ack/sctp)",
                ));
            }
        } else {
            if ports.is_empty() {
                return Err(CliError::new(
                    Kind::Usage,
                    "tcp and udp discovery probes need --discovery-ports (as do tcp-ack and sctp)",
                ));
            }
            let exclude = exclude_ports
                .iter()
                .filter(|term| {
                    term.0
                        .transport
                        .is_none_or(|transport| port_transports.contains(&transport))
                })
                .map(|term| term.0.clone())
                .collect();
            let (selected, excluded_counts) =
                packetcraftr::scan::select_endpoints_with_exclusion_counts(
                    &packetcraftr::scan::PortSelection {
                        transports: port_transports.clone(),
                        include: ports.into_iter().map(|term| term.0).collect(),
                        exclude,
                    },
                    packetcraftr::scan::catalog::bundled(),
                    max_ports,
                )
                .map_err(|error| {
                    CliError::from_classification(
                        error.classification(),
                        format!("--discovery-ports: {error}"),
                        error.causes(),
                    )
                })?;
            excluded_total = excluded_total.saturating_add(selected.excluded);
            excluded_total = excluded_total.saturating_add(
                excluded_counts.get(&Transport::Tcp).copied().unwrap_or(0)
                    * tcp_modes.len().saturating_sub(1),
            );
            for endpoint in selected.endpoints {
                match endpoint {
                    probe::Endpoint::Tcp { port } => {
                        for &is_ack in &tcp_modes {
                            options.probes.push(if is_ack {
                                probe::Endpoint::TcpAck { port }
                            } else {
                                probe::Endpoint::Tcp { port }
                            });
                        }
                    }
                    other => options.probes.push(other),
                }
            }
        }
        if !wants_ip_protocols {
            if !ip_protocols.is_empty() {
                return Err(CliError::new(
                    Kind::Usage,
                    "--discovery-ip-protocols needs ip among --discovery-probes",
                ));
            }
        } else {
            if ip_protocols.is_empty() {
                return Err(CliError::new(
                    Kind::Usage,
                    "ip discovery probes need --discovery-ip-protocols",
                ));
            }
            let selected = packetcraftr::scan::select_ip_protocols(
                &packetcraftr::scan::IpProtocolSelection {
                    include: ip_protocols.into_iter().map(|term| term.0).collect(),
                    exclude: exclude_ip_protocols.iter().map(|term| term.0).collect(),
                },
                max_ports,
            )
            .map_err(|error| {
                CliError::from_classification(
                    error.classification(),
                    format!("--discovery-ip-protocols: {error}"),
                    error.causes(),
                )
            })?;
            excluded_total = excluded_total.saturating_add(selected.excluded);
            options.probes.extend(selected.endpoints);
        }
        Ok(PreparedDiscovery {
            options,
            excluded: excluded_total,
            port_transports,
        })
    }
}

#[cfg(test)]
mod tests;
