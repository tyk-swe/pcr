// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::scan::{
    DiscoveryProbe, DiscoverySelection, EndpointSelection, IpProtocolSelection, PortSelection,
    PortTransport, Prepared, Probes, Selection, TcpScan,
};
use packetcraftr_core::error::Kind;

use super::arguments;
use crate::errors::CliError;

#[derive(Clone)]
pub(super) struct Inputs {
    pub(super) transports: Vec<arguments::Transport>,
    pub(super) ports: Vec<arguments::PortTerm>,
    pub(super) exclude_ports: Vec<arguments::PortTerm>,
    pub(super) ip_protocols: Vec<arguments::IpProtocolTerm>,
    pub(super) exclude_ip_protocols: Vec<arguments::IpProtocolTerm>,
    pub(super) discovery: Option<arguments::Discovery>,
    pub(super) discovery_probes: Vec<arguments::DiscoveryProbe>,
    pub(super) discovery_ports: Vec<arguments::PortTerm>,
    pub(super) discovery_ip_protocols: Vec<arguments::IpProtocolTerm>,
    pub(super) unresponsive: Option<arguments::UnresponsiveHosts>,
    pub(super) max_ports: usize,
    pub(super) tcp_scan: TcpScan,
    pub(super) sctp_scan: packetcraftr::scan::SctpScan,
}

pub(super) fn prepare(inputs: Inputs, listing: bool) -> Result<Prepared, CliError> {
    let Inputs {
        transports,
        ports,
        exclude_ports,
        ip_protocols,
        exclude_ip_protocols,
        discovery: discovery_mode,
        discovery_probes,
        discovery_ports,
        discovery_ip_protocols,
        unresponsive,
        max_ports,
        tcp_scan,
        sctp_scan,
    } = inputs;
    let transports = port_transports(&transports)?;
    let protocol_selection = IpProtocolSelection {
        include: ip_protocols.iter().map(|term| term.0).collect(),
        exclude: exclude_ip_protocols.iter().map(|term| term.0).collect(),
    };
    if listing && discovery_mode.is_some() {
        return Err(usage(
            "--list sends no probe; remove --discovery, --reverse-dns, and --traceroute",
        ));
    }
    let selection = match transports {
        TransportShape::Ports(transports) => {
            if !protocol_selection.include.is_empty() || !protocol_selection.exclude.is_empty() {
                return Err(usage(
                    "--ip-protocols and --exclude-ip-protocols require --transport ip",
                ));
            }
            let ports = PortSelection::new(
                transports,
                ports.into_iter().map(|term| term.0).collect(),
                exclude_ports.iter().map(|term| term.0.clone()).collect(),
            )
            .map_err(CliError::classified)?;
            EndpointSelection::Ports(ports)
        }
        TransportShape::Icmp => {
            if !ports.is_empty() || !exclude_ports.is_empty() {
                return Err(usage(
                    "--ports and --exclude-ports do not apply to portless ICMP echo scans",
                ));
            }
            if !protocol_selection.include.is_empty() || !protocol_selection.exclude.is_empty() {
                return Err(usage(
                    "--ip-protocols and --exclude-ip-protocols require --transport ip",
                ));
            }
            EndpointSelection::Icmp
        }
        TransportShape::Ip => {
            if !ports.is_empty() || !exclude_ports.is_empty() {
                return Err(usage(
                    "--ports and --exclude-ports do not apply to portless IP-protocol scans; use --ip-protocols",
                ));
            }
            EndpointSelection::IpProtocols(protocol_selection)
        }
    };
    let discovery = match discovery_mode {
        None => DiscoverySelection::Omitted,
        Some(arguments::Discovery::Skip) => {
            if !discovery_probes.is_empty()
                || !discovery_ports.is_empty()
                || !discovery_ip_protocols.is_empty()
                || unresponsive.is_some()
            {
                return Err(usage("discovery probes need a discovery stage that runs"));
            }
            DiscoverySelection::Skipped
        }
        Some(mode @ (arguments::Discovery::Before | arguments::Discovery::Only)) => {
            if mode == arguments::Discovery::Only && unresponsive.is_some() {
                return Err(usage("discovery-only requests scan no host"));
            }
            let port_transports = discovery_probes
                .iter()
                .filter_map(|probe| match probe {
                    arguments::DiscoveryProbe::Tcp | arguments::DiscoveryProbe::TcpAck => {
                        Some(PortTransport::Tcp)
                    }
                    arguments::DiscoveryProbe::Udp => Some(PortTransport::Udp),
                    arguments::DiscoveryProbe::Sctp => Some(PortTransport::Sctp),
                    _ => None,
                })
                .fold(Vec::new(), |mut transports, transport| {
                    if !transports.contains(&transport) {
                        transports.push(transport);
                    }
                    transports
                });
            let ports = if discovery_ports.is_empty() {
                None
            } else {
                Some(
                    PortSelection::new(
                        port_transports,
                        discovery_ports.into_iter().map(|term| term.0).collect(),
                        exclude_ports.iter().map(|term| term.0.clone()).collect(),
                    )
                    .map_err(CliError::classified)?,
                )
            };
            let probes = Probes::new(
                discovery_probes.into_iter().map(discovery_probe).collect(),
                ports,
                (!discovery_ip_protocols.is_empty()).then_some(IpProtocolSelection {
                    include: discovery_ip_protocols.iter().map(|term| term.0).collect(),
                    exclude: exclude_ip_protocols.iter().map(|term| term.0).collect(),
                }),
            )
            .map_err(CliError::classified)?;
            if mode == arguments::Discovery::Only {
                DiscoverySelection::Only(probes)
            } else {
                DiscoverySelection::Before {
                    probes,
                    unresponsive: unresponsive.map_or_else(Default::default, Into::into),
                }
            }
        }
    };
    let scan = if !selection.has_terms() {
        None
    } else {
        Some(selection)
    };
    Selection::new(scan, discovery)
        .prepare(
            packetcraftr::scan::catalog::bundled(),
            max_ports,
            tcp_scan,
            sctp_scan,
            listing,
        )
        .map_err(CliError::classified)
}

enum TransportShape {
    Ports(Vec<PortTransport>),
    Icmp,
    Ip,
}

fn port_transports(requested: &[arguments::Transport]) -> Result<TransportShape, CliError> {
    let mut transports = Vec::new();
    let mut icmp = false;
    let mut ip = false;
    for transport in requested {
        match transport {
            arguments::Transport::Tcp | arguments::Transport::Udp | arguments::Transport::Sctp => {
                let transport = match transport {
                    arguments::Transport::Tcp => PortTransport::Tcp,
                    arguments::Transport::Udp => PortTransport::Udp,
                    arguments::Transport::Sctp => PortTransport::Sctp,
                    _ => unreachable!(),
                };
                if !transports.contains(&transport) {
                    transports.push(transport);
                }
            }
            arguments::Transport::Icmp => icmp = true,
            arguments::Transport::Ip => ip = true,
        }
    }
    if icmp && (ip || !transports.is_empty()) {
        return Err(usage(
            "--transport icmp is portless and cannot be combined with tcp or udp (or sctp/ip)",
        ));
    }
    if ip && !transports.is_empty() {
        return Err(usage(
            "--transport ip is portless and cannot be combined with tcp or udp (or sctp/icmp)",
        ));
    }
    Ok(if icmp {
        TransportShape::Icmp
    } else if ip {
        TransportShape::Ip
    } else if requested.is_empty() {
        TransportShape::Ports(vec![PortTransport::Tcp])
    } else {
        TransportShape::Ports(transports)
    })
}

fn discovery_probe(probe: arguments::DiscoveryProbe) -> DiscoveryProbe {
    match probe {
        arguments::DiscoveryProbe::Icmp => DiscoveryProbe::Icmp,
        arguments::DiscoveryProbe::IcmpTimestamp => DiscoveryProbe::IcmpTimestamp,
        arguments::DiscoveryProbe::IcmpNetmask => DiscoveryProbe::IcmpNetmask,
        arguments::DiscoveryProbe::Neighbor => DiscoveryProbe::Neighbor,
        arguments::DiscoveryProbe::Tcp => DiscoveryProbe::Tcp,
        arguments::DiscoveryProbe::TcpAck => DiscoveryProbe::TcpAck,
        arguments::DiscoveryProbe::Udp => DiscoveryProbe::Udp,
        arguments::DiscoveryProbe::Sctp => DiscoveryProbe::Sctp,
        arguments::DiscoveryProbe::Ip => DiscoveryProbe::Ip,
    }
}

fn usage(message: &'static str) -> CliError {
    CliError::new(Kind::Usage, message)
}
