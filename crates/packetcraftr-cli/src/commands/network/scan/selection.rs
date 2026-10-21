// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use packetcraftr::probe::{self, Transport};
use packetcraftr::scan::{
    MAX_UDP_PAYLOAD_BYTES, Selected, discovery,
    profile::{self, UdpProfile},
};
use packetcraftr_core::document::udp_profiles::{self, MAX_PROFILE_BYTES};
use packetcraftr_core::error::{Classified, Kind};

use super::arguments;
use crate::errors::CliError;
use crate::input::{InputKind, manifest, read_bounded_file_allow_empty};

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

pub(super) fn read_udp_payload(
    udp: bool,
    hex: Option<&str>,
    path: Option<&Path>,
) -> Result<Bytes, CliError> {
    if (hex.is_some() || path.is_some()) && !udp {
        return Err(CliError::new(
            Kind::Usage,
            "--udp-payload-hex and --udp-payload-file require --transport udp",
        ));
    }
    if let Some(hex) = hex {
        // Bound both source text and decoded digits before parse_hex allocates.
        let digits = hex
            .strip_prefix("0x")
            .or_else(|| hex.strip_prefix("0X"))
            .unwrap_or(hex);
        if hex.len() > MAX_UDP_PAYLOAD_BYTES * 4 + 2
            || digits
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
                .count()
                > MAX_UDP_PAYLOAD_BYTES * 2
        {
            return Err(CliError::new(
                Kind::Usage,
                "UDP payload exceeds 65507 bytes or its bounded hex representation",
            ));
        }
        return packetcraftr_core::layer::parse_hex(hex)
            .map_err(|source| CliError::caused(Kind::Usage, &source));
    }
    if let Some(path) = path {
        if manifest::is_stdin(path) {
            return crate::input::read_stdin_bounded_allow_empty(
                MAX_UDP_PAYLOAD_BYTES,
                InputKind::Payload,
            )
            .map(Bytes::from);
        }
        return read_bounded_file_allow_empty(path, MAX_UDP_PAYLOAD_BYTES, InputKind::Payload)
            .map(Bytes::from);
    }
    Ok(Bytes::new())
}

pub(super) fn load_udp_profiles(
    path: Option<&Path>,
    udp: bool,
) -> Result<BTreeMap<u16, Arc<UdpProfile>>, CliError> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    if !udp {
        return Err(CliError::new(
            Kind::Usage,
            "--udp-profiles requires --transport udp",
        ));
    }
    let document = if manifest::is_stdin(path) {
        crate::input::read_stdin_bounded(MAX_PROFILE_BYTES, InputKind::UdpProfiles)?
    } else {
        crate::input::read_bounded_json_document(path, MAX_PROFILE_BYTES)?
    };
    let assignments = udp_profiles::parse(&document).map_err(CliError::classified)?;
    profile::compile(assignments).map_err(CliError::classified)
}

pub(super) struct Ingested {
    pub(crate) targets: packetcraftr::target::Selection,
    pub(crate) origins: Vec<manifest::Declaration>,
}

pub(super) fn ingest_targets(
    positional: &[String],
    targets_file: &[PathBuf],
    exclusions: &[packetcraftr::target::Network],
    exclude_file: &[PathBuf],
    max_manifest_bytes: Option<usize>,
    max_manifest_lines: Option<usize>,
) -> Result<Ingested, CliError> {
    let bounds = manifest::ManifestBounds::new(
        max_manifest_bytes.unwrap_or(manifest::MAX_MANIFEST_BYTES),
        max_manifest_lines.unwrap_or(manifest::MAX_MANIFEST_LINES),
    )?;
    let mut budget = bounds.budget();
    let mut origins = positional
        .iter()
        .enumerate()
        .map(|(position, target)| manifest::Declaration {
            token: target.clone(),
            source: manifest::DeclarationSource::Argument {
                position: position + 1,
            },
            line: None,
        })
        .collect::<Vec<_>>();
    origins.extend(manifest::read_with_budget(
        &manifest_sources(targets_file),
        &mut budget,
    )?);
    let include = parse_declarations(&origins)?;
    if include.is_empty() {
        return Err(CliError::new(
            Kind::Usage,
            "at least one target is required: pass TARGET or --targets-file",
        ));
    }
    let mut exclude = exclusions.to_vec();
    exclude.extend(parse_declarations::<packetcraftr::target::Network>(
        &manifest::read_with_budget(&manifest_sources(exclude_file), &mut budget)?,
    )?);
    Ok(Ingested {
        targets: packetcraftr::target::Selection { include, exclude },
        origins,
    })
}

fn manifest_sources(paths: &[PathBuf]) -> Vec<manifest::ManifestSource> {
    paths
        .iter()
        .map(|path| manifest::ManifestSource::open(path))
        .collect()
}

fn parse_declarations<T>(declarations: &[manifest::Declaration]) -> Result<Vec<T>, CliError>
where
    T: std::str::FromStr,
    T::Err: Classified,
{
    declarations
        .iter()
        .map(|declaration| {
            declaration
                .token
                .parse()
                .map_err(|source| declaration_error(source, declaration))
        })
        .collect()
}

fn declaration_error(source: impl Classified, declaration: &manifest::Declaration) -> CliError {
    CliError::from_classification(
        source.classification(),
        format!("invalid declaration at {declaration}: {source}"),
        crate::errors::source_causes(&source),
    )
    .with_context(source.context())
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr::scan::{IpProtocolSpec, PortSpec, Selector, Term};

    fn port(transport: Option<Transport>, value: u16) -> arguments::PortTerm {
        arguments::PortTerm(Term {
            transport,
            selector: Selector::Ports(PortSpec::Single(value)),
        })
    }

    fn protocol(value: u8) -> arguments::IpProtocolTerm {
        arguments::IpProtocolTerm(IpProtocolSpec::Single(value))
    }

    fn endpoint_request(
        transports: &[Transport],
        ports: Vec<arguments::PortTerm>,
        exclude_ports: Vec<arguments::PortTerm>,
        ip_protocols: Vec<arguments::IpProtocolTerm>,
        exclude_ip_protocols: Vec<arguments::IpProtocolTerm>,
    ) -> EndpointRequest {
        EndpointRequest {
            transports: transports.to_vec(),
            ports,
            exclude_ports,
            ip_protocols,
            exclude_ip_protocols,
            max_ports: 1024,
        }
    }

    fn discovery_request(probes: Vec<arguments::DiscoveryProbe>) -> DiscoveryRequest {
        DiscoveryRequest {
            mode: Some(arguments::Discovery::Before),
            probes,
            ports: vec![port(None, 22), port(None, 53)],
            exclude_ports: vec![port(Some(Transport::Tcp), 53)],
            ip_protocols: Vec::new(),
            exclude_ip_protocols: Vec::new(),
            unresponsive: None,
            max_ports: 1024,
        }
    }

    #[test]
    fn live_port_selection_requires_omitted_ports() {
        let error = endpoint_request(&[Transport::Tcp], vec![], vec![], vec![], vec![])
            .select()
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid scan ports: TCP and UDP scans require at least one destination port"
        );
    }

    #[test]
    fn listing_omits_an_unrequested_default_port_selection() {
        let selected = endpoint_request(&[Transport::Tcp], vec![], vec![], vec![], vec![])
            .select_if_requested()
            .expect("an omitted list selection is valid");
        assert!(selected.is_none());
    }

    #[test]
    fn ip_protocol_only_selection_uses_protocol_endpoints() {
        let selected = endpoint_request(
            &[Transport::Ip],
            vec![],
            vec![],
            vec![protocol(1), protocol(6)],
            vec![protocol(6)],
        )
        .select()
        .unwrap();
        assert_eq!(selected.endpoints, [probe::Endpoint::Ip { protocol: 1 }]);
        assert_eq!(selected.excluded, 1);
    }

    #[test]
    fn invalid_port_and_protocol_combinations_keep_their_messages() {
        let cases = [
            (
                endpoint_request(
                    &[Transport::Ip],
                    vec![port(None, 80)],
                    vec![],
                    vec![],
                    vec![],
                ),
                "--ports and --exclude-ports do not apply to portless IP-protocol scans; use --ip-protocols",
            ),
            (
                endpoint_request(
                    &[Transport::Icmp],
                    vec![port(None, 80)],
                    vec![],
                    vec![],
                    vec![],
                ),
                "--ports and --exclude-ports do not apply to portless ICMP echo scans",
            ),
            (
                endpoint_request(
                    &[Transport::Tcp],
                    vec![port(None, 80)],
                    vec![],
                    vec![protocol(1)],
                    vec![],
                ),
                "--ip-protocols and --exclude-ip-protocols require --transport ip",
            ),
        ];
        for (request, expected) in cases {
            assert_eq!(request.select().unwrap_err().to_string(), expected);
        }
    }

    #[test]
    fn listing_preserves_icmp_combined_invalid_option_precedence() {
        let listing = endpoint_request(
            &[Transport::Icmp],
            vec![port(None, 80)],
            vec![],
            vec![protocol(1)],
            vec![],
        )
        .select_if_requested()
        .unwrap_err();
        assert_eq!(
            listing.to_string(),
            "--ip-protocols and --exclude-ip-protocols require --transport ip"
        );

        let scan = endpoint_request(
            &[Transport::Icmp],
            vec![port(None, 80)],
            vec![],
            vec![protocol(1)],
            vec![],
        )
        .select()
        .unwrap_err();
        assert_eq!(
            scan.to_string(),
            "--ports and --exclude-ports do not apply to portless ICMP echo scans"
        );
    }

    #[test]
    fn transport_specific_exclusions_only_remove_matching_endpoints() {
        let selected = endpoint_request(
            &[Transport::Tcp, Transport::Udp],
            vec![port(None, 53), port(None, 80)],
            vec![port(Some(Transport::Tcp), 53)],
            vec![],
            vec![],
        )
        .select()
        .unwrap();
        assert_eq!(
            selected.endpoints,
            [
                probe::Endpoint::Udp { port: 53 },
                probe::Endpoint::Tcp { port: 80 },
                probe::Endpoint::Udp { port: 80 },
            ]
        );
        assert_eq!(selected.excluded, 1);
    }

    #[test]
    fn scan_exclusions_keep_terms_discovery_did_not_consume() {
        let mut request = endpoint_request(
            &[Transport::Tcp],
            vec![port(None, 53), port(None, 80)],
            vec![
                port(Some(Transport::Udp), 53),
                port(Some(Transport::Tcp), 80),
            ],
            vec![],
            vec![],
        );
        request.retain_scan_exclusions(&[Transport::Udp]);
        let selected = request.select().unwrap();
        assert_eq!(selected.endpoints, [probe::Endpoint::Tcp { port: 53 }]);
        assert_eq!(selected.excluded, 1);
    }

    #[test]
    fn tcp_and_tcp_ack_discovery_expansion_is_deduplicated_and_counted() {
        let prepared = discovery_request(vec![
            arguments::DiscoveryProbe::Tcp,
            arguments::DiscoveryProbe::TcpAck,
            arguments::DiscoveryProbe::Tcp,
            arguments::DiscoveryProbe::TcpAck,
        ])
        .prepare()
        .unwrap();
        assert_eq!(prepared.port_transports, [Transport::Tcp]);
        assert_eq!(
            prepared.options.probes,
            [
                probe::Endpoint::Tcp { port: 22 },
                probe::Endpoint::TcpAck { port: 22 },
            ]
        );
        assert_eq!(prepared.excluded, 2);
    }
}
