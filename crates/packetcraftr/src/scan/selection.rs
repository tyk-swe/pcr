// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Checked endpoint and discovery selection shared by listing and execution.

use super::Error;
use super::catalog::{Catalog, catalog_transport};
use crate::probe::{self, Transport};

pub const MAX_PORT_TERMS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PortTransport {
    Tcp,
    Udp,
    Sctp,
}

impl PortTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
        }
    }
}

impl std::fmt::Display for PortTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<PortTransport> for Transport {
    fn from(value: PortTransport) -> Self {
        match value {
            PortTransport::Tcp => Self::Tcp,
            PortTransport::Udp => Self::Udp,
            PortTransport::Sctp => Self::Sctp,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortSpec {
    Single(u16),
    RangeInclusive { start: u16, end: u16 },
}

impl PortSpec {
    pub fn new(start: u16, end: u16) -> Result<Self, Error> {
        (start <= end)
            .then_some(Self::RangeInclusive { start, end })
            .ok_or_else(|| invalid(format!("port range {start}-{end} is descending")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    Ports(PortSpec),
    Name(String),
    Preset(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term {
    pub transport: Option<PortTransport>,
    pub selector: Selector,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortSelection {
    transports: Vec<PortTransport>,
    include: Vec<Term>,
    exclude: Vec<Term>,
}

impl PortSelection {
    pub fn new(
        transports: Vec<PortTransport>,
        include: Vec<Term>,
        exclude: Vec<Term>,
    ) -> Result<Self, Error> {
        if transports.is_empty() {
            return Err(invalid(
                "port selections need TCP and/or UDP (or SCTP) transports",
            ));
        }
        let mut unique = Vec::with_capacity(transports.len());
        for transport in transports {
            if !unique.contains(&transport) {
                unique.push(transport);
            }
        }
        check_term_count(&include, &exclude, "port terms")?;
        Ok(Self {
            transports: unique,
            include,
            exclude,
        })
    }

    pub fn transports(&self) -> &[PortTransport] {
        &self.transports
    }

    fn without_consumed_exclusions(&self, discovery: &[PortTransport]) -> Self {
        Self {
            transports: self.transports.clone(),
            include: self.include.clone(),
            exclude: self
                .exclude
                .iter()
                .filter(|term| {
                    let applies = term.transport.map_or_else(
                        || !self.transports.is_empty(),
                        |transport| self.transports.contains(&transport),
                    );
                    applies
                        || !discovery.iter().any(|transport| {
                            term.transport.is_none_or(|excluded| excluded == *transport)
                        })
                })
                .cloned()
                .collect(),
        }
    }

    fn discovery_exclusions(&self) -> Vec<Term> {
        self.exclude
            .iter()
            .filter(|term| {
                term.transport
                    .is_none_or(|transport| self.transports.contains(&transport))
            })
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpProtocolSelection {
    pub include: Vec<IpProtocolSpec>,
    pub exclude: Vec<IpProtocolSpec>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpProtocolSpec {
    Single(u8),
    RangeInclusive { start: u8, end: u8 },
}

impl IpProtocolSpec {
    pub fn new(start: u8, end: u8) -> Result<Self, Error> {
        (start <= end)
            .then_some(Self::RangeInclusive { start, end })
            .ok_or_else(|| invalid(format!("IP protocol range {start}-{end} is descending")))
    }

    fn values(self) -> impl Iterator<Item = u8> {
        let (start, end) = match self {
            Self::Single(protocol) => (protocol, protocol),
            Self::RangeInclusive { start, end } => (start, end),
        };
        debug_assert!(start <= end);
        start..=end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanKind {
    Ports,
    Icmp,
    IpProtocols,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointSelection {
    Ports(PortSelection),
    Icmp,
    IpProtocols(IpProtocolSelection),
}

impl Selection {
    fn discovery_only_scan_is_invalid(&self) -> bool {
        matches!(self.discovery, DiscoverySelection::Only(_))
            && self.scan.as_ref().is_some_and(|scan| {
                scan.has_includes()
                    || matches!(scan, EndpointSelection::IpProtocols(protocols) if !protocols.exclude.is_empty())
            })
    }
}

impl EndpointSelection {
    fn has_includes(&self) -> bool {
        match self {
            Self::Ports(selection) => !selection.include.is_empty(),
            Self::Icmp => true,
            Self::IpProtocols(selection) => !selection.include.is_empty(),
        }
    }

    pub fn has_terms(&self) -> bool {
        match self {
            Self::Ports(selection) => {
                !selection.include.is_empty() || !selection.exclude.is_empty()
            }
            Self::Icmp => false,
            Self::IpProtocols(selection) => {
                !selection.include.is_empty() || !selection.exclude.is_empty()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryProbe {
    Icmp,
    IcmpTimestamp,
    IcmpNetmask,
    Neighbor,
    Tcp,
    TcpAck,
    Udp,
    Sctp,
    Ip,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoverySelection {
    Omitted,
    Skipped,
    Before {
        probes: Probes,
        unresponsive: super::discovery::Unresponsive,
    },
    Only(Probes),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probes {
    endpoints: Vec<DiscoveryProbe>,
    ports: Option<PortSelection>,
    ip_protocols: Option<IpProtocolSelection>,
}

impl Probes {
    pub fn new(
        endpoints: Vec<DiscoveryProbe>,
        ports: Option<PortSelection>,
        ip_protocols: Option<IpProtocolSelection>,
    ) -> Result<Self, Error> {
        Self {
            endpoints,
            ports,
            ip_protocols,
        }
        .validate()
    }

    fn validate(self) -> Result<Self, Error> {
        let requests_ports = self.endpoints.iter().any(|probe| {
            matches!(
                probe,
                DiscoveryProbe::Tcp
                    | DiscoveryProbe::TcpAck
                    | DiscoveryProbe::Udp
                    | DiscoveryProbe::Sctp
            )
        });
        match (requests_ports, self.ports.is_some()) {
            (true, false) => {
                return Err(Error::InvalidDiscovery {
                    message: "tcp and udp discovery probes need --discovery-ports (as do tcp-ack and sctp)".to_owned(),
                });
            }
            (false, true) => {
                return Err(Error::InvalidDiscovery {
                    message: "--discovery-ports needs tcp or udp among --discovery-probes (or tcp-ack/sctp)".to_owned(),
                });
            }
            _ => {}
        }
        match (
            self.endpoints.contains(&DiscoveryProbe::Ip),
            self.ip_protocols.is_some(),
        ) {
            (true, false) => {
                return Err(Error::InvalidDiscovery {
                    message: "ip discovery probes need --discovery-ip-protocols".to_owned(),
                });
            }
            (false, true) => {
                return Err(Error::InvalidDiscovery {
                    message: "--discovery-ip-protocols needs ip among --discovery-probes"
                        .to_owned(),
                });
            }
            _ => {}
        }
        Ok(self)
    }
}

impl DiscoverySelection {
    fn port_transports(&self) -> &[PortTransport] {
        match self {
            Self::Before { probes, .. } | Self::Only(probes) => {
                probes.ports.as_ref().map_or(&[], PortSelection::transports)
            }
            Self::Omitted | Self::Skipped => &[],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    scan: Option<EndpointSelection>,
    discovery: DiscoverySelection,
}

impl Selection {
    pub fn new(scan: Option<EndpointSelection>, discovery: DiscoverySelection) -> Self {
        Self { scan, discovery }
    }

    pub fn prepare(
        self,
        catalog: &Catalog,
        max_ports: usize,
        tcp_scan: super::TcpScan,
        sctp_scan: super::SctpScan,
        allow_empty: bool,
    ) -> Result<Prepared, Error> {
        if self.discovery_only_scan_is_invalid() {
            return Err(Error::InvalidDiscovery {
                message: "--discovery only probes no scan port; remove --ports and --ip-protocols"
                    .to_owned(),
            });
        }
        let publish_scan = self.scan.as_ref().is_some_and(EndpointSelection::has_terms);
        let scan = self.scan.filter(|selection| {
            matches!(selection, EndpointSelection::Icmp)
                || selection.has_includes()
                || matches!(
                    selection,
                    EndpointSelection::IpProtocols(protocols)
                        if !protocols.exclude.is_empty()
                )
        });
        if tcp_scan != super::TcpScan::Syn && scan.is_none() {
            return Err(Error::InvalidLimit {
                field: "tcp_scan",
                value: u64::from(tcp_scan.flags()),
                reason: format!(
                    "{} scans require at least one TCP scan endpoint",
                    tcp_scan.as_str()
                ),
            });
        }
        if sctp_scan != super::SctpScan::Init && scan.is_none() {
            return Err(Error::InvalidLimit {
                field: "sctp_scan",
                value: u64::from(sctp_scan.chunk_type()),
                reason: format!(
                    "{} scans require at least one SCTP scan endpoint",
                    sctp_scan.as_str()
                ),
            });
        }
        let shared_ports = self.discovery.port_transports().to_owned();
        let discovery = prepare_discovery(self.discovery, catalog, max_ports)?;
        let scan = scan
            .map(|selection| prepare_scan(selection, catalog, max_ports, &shared_ports))
            .transpose()?;
        Prepared::new(
            scan,
            discovery,
            max_ports,
            tcp_scan,
            sctp_scan,
            allow_empty,
            publish_scan,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    scan: Option<Selected>,
    discovery: super::discovery::Options,
    discovery_excluded: usize,
    publish_scan: bool,
    tcp_scan: super::TcpScan,
    sctp_scan: super::SctpScan,
}

impl Prepared {
    fn new(
        scan: Option<Selected>,
        discovery_prepared: DiscoveryPrepared,
        max_ports: usize,
        tcp_scan: super::TcpScan,
        sctp_scan: super::SctpScan,
        allow_empty: bool,
        publish_scan: bool,
    ) -> Result<Self, Error> {
        let discovery = discovery_prepared.options;
        let endpoints = scan
            .as_ref()
            .map_or(&[] as _, |selected| selected.endpoints.as_slice());
        if tcp_scan != super::TcpScan::Syn
            && !endpoints
                .iter()
                .any(|endpoint| endpoint.transport() == Transport::Tcp)
        {
            return Err(Error::InvalidLimit {
                field: "tcp_scan",
                value: u64::from(tcp_scan.flags()),
                reason: format!(
                    "{} scans require at least one TCP scan endpoint",
                    tcp_scan.as_str()
                ),
            });
        }
        if sctp_scan != super::SctpScan::Init
            && !endpoints
                .iter()
                .any(|endpoint| endpoint.transport() == Transport::Sctp)
        {
            return Err(Error::InvalidLimit {
                field: "sctp_scan",
                value: u64::from(sctp_scan.chunk_type()),
                reason: format!(
                    "{} scans require at least one SCTP scan endpoint",
                    sctp_scan.as_str()
                ),
            });
        }
        if endpoints.is_empty()
            && !matches!(discovery.mode(), super::discovery::Mode::Only)
            && !(allow_empty && scan.is_none())
        {
            return Err(invalid(
                "TCP and UDP scans require at least one destination port; SCTP and IP-protocol scans also require at least one destination endpoint",
            ));
        }
        if !endpoints.is_empty() && discovery.mode() == super::discovery::Mode::Only {
            return Err(Error::InvalidDiscovery {
                message: "discovery-only requests probe no scan endpoint".to_owned(),
            });
        }
        let distinct = endpoints
            .iter()
            .chain(discovery.probes())
            .collect::<std::collections::HashSet<_>>();
        if distinct.len() > max_ports {
            return Err(Error::InvalidLimit {
                field: "ports",
                value: u64::try_from(distinct.len()).unwrap_or(u64::MAX),
                reason: format!("exceeds max_ports={max_ports}"),
            });
        }
        Ok(Self {
            scan,
            discovery,
            discovery_excluded: discovery_prepared.excluded,
            publish_scan,
            tcp_scan,
            sctp_scan,
        })
    }

    pub fn scan(&self) -> Option<&Selected> {
        self.scan.as_ref()
    }

    pub const fn publish_scan(&self) -> bool {
        self.publish_scan
    }

    pub fn endpoints(&self) -> &[probe::Endpoint] {
        self.scan.as_ref().map_or(&[], Selected::endpoints)
    }

    pub fn discovery(&self) -> &super::discovery::Options {
        &self.discovery
    }

    pub fn excluded_endpoints(&self) -> usize {
        self.scan.as_ref().map_or(0, Selected::excluded)
    }

    pub fn discovery_excluded(&self) -> usize {
        self.discovery_excluded
    }

    pub const fn tcp_scan(&self) -> super::TcpScan {
        self.tcp_scan
    }

    pub const fn sctp_scan(&self) -> super::SctpScan {
        self.sctp_scan
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selected {
    kind: ScanKind,
    endpoints: Vec<probe::Endpoint>,
    excluded: usize,
}

impl Selected {
    pub fn kind(&self) -> ScanKind {
        self.kind
    }

    pub fn endpoints(&self) -> &[probe::Endpoint] {
        &self.endpoints
    }

    pub fn excluded(&self) -> usize {
        self.excluded
    }

    pub fn ip_protocols(&self) -> impl Iterator<Item = u8> + '_ {
        self.endpoints
            .iter()
            .filter_map(|endpoint| endpoint.ip_protocol())
    }
}

fn prepare_scan(
    selection: EndpointSelection,
    catalog: &Catalog,
    max_ports: usize,
    discovery_ports: &[PortTransport],
) -> Result<Selected, Error> {
    let (kind, endpoints, excluded) = match selection {
        EndpointSelection::Icmp => (ScanKind::Icmp, vec![probe::Endpoint::Icmp], 0),
        EndpointSelection::IpProtocols(selection) => {
            let selected = expand_protocols(&selection, max_ports)?;
            (
                ScanKind::IpProtocols,
                selected
                    .values
                    .into_iter()
                    .map(|protocol| probe::Endpoint::Ip { protocol })
                    .collect(),
                selected.excluded,
            )
        }
        EndpointSelection::Ports(selection) => {
            let selection = selection.without_consumed_exclusions(discovery_ports);
            let selected = expand_ports(&selection, catalog, max_ports)?;
            (
                ScanKind::Ports,
                selected.values.into_iter().map(Port::endpoint).collect(),
                selected.excluded,
            )
        }
    };
    Ok(Selected {
        kind,
        endpoints,
        excluded,
    })
}

struct DiscoveryPrepared {
    options: super::discovery::Options,
    excluded: usize,
}

fn prepare_discovery(
    selection: DiscoverySelection,
    catalog: &Catalog,
    max_ports: usize,
) -> Result<DiscoveryPrepared, Error> {
    use super::discovery::{Options, Plan, Unresponsive};
    enum Kind {
        Before { unresponsive: Unresponsive },
        Only,
    }
    let (kind, probes) = match selection {
        DiscoverySelection::Omitted => {
            return Ok(DiscoveryPrepared {
                options: Options::Omitted,
                excluded: 0,
            });
        }
        DiscoverySelection::Skipped => {
            return Ok(DiscoveryPrepared {
                options: Options::Skipped,
                excluded: 0,
            });
        }
        DiscoverySelection::Before {
            probes,
            unresponsive,
        } => (Kind::Before { unresponsive }, probes),
        DiscoverySelection::Only(probes) => (Kind::Only, probes),
    };
    let Probes {
        endpoints: probes,
        ports,
        ip_protocols,
    } = probes;
    let probes = if probes.is_empty() {
        vec![DiscoveryProbe::Icmp]
    } else {
        probes
    };
    let mut endpoints = Vec::new();
    let mut excluded = 0usize;
    let mut neighbor = false;
    for probe in &probes {
        match probe {
            DiscoveryProbe::Icmp => push_unique(&mut endpoints, probe::Endpoint::Icmp),
            DiscoveryProbe::IcmpTimestamp => {
                push_unique(&mut endpoints, probe::Endpoint::IcmpTimestamp);
            }
            DiscoveryProbe::IcmpNetmask => {
                push_unique(&mut endpoints, probe::Endpoint::IcmpNetmask);
            }
            DiscoveryProbe::Neighbor => neighbor = true,
            DiscoveryProbe::Tcp
            | DiscoveryProbe::TcpAck
            | DiscoveryProbe::Udp
            | DiscoveryProbe::Sctp
            | DiscoveryProbe::Ip => {}
        }
    }
    let tcp_modes: Vec<bool> = probes
        .iter()
        .filter_map(|probe| match probe {
            DiscoveryProbe::Tcp => Some(false),
            DiscoveryProbe::TcpAck => Some(true),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if let Some(ports) = ports {
        let exclusion_terms = ports.discovery_exclusions();
        let selection = PortSelection::new(ports.transports, ports.include, exclusion_terms)?;
        let selected = expand_ports(&selection, catalog, max_ports)?;
        let tcp_excluded = selected
            .excluded_tcp
            .iter()
            .map(|word| usize::try_from(word.count_ones()).unwrap_or(usize::MAX))
            .sum::<usize>();
        excluded = excluded.saturating_add(selected.excluded);
        excluded =
            excluded.saturating_add(tcp_excluded.saturating_mul(tcp_modes.len().saturating_sub(1)));
        for port in selected.values {
            match port.transport {
                PortTransport::Tcp => {
                    for is_ack in &tcp_modes {
                        endpoints.push(if *is_ack {
                            probe::Endpoint::TcpAck { port: port.number }
                        } else {
                            probe::Endpoint::Tcp { port: port.number }
                        });
                    }
                }
                PortTransport::Udp | PortTransport::Sctp => endpoints.push(port.endpoint()),
            }
        }
    }
    if let Some(protocols) = ip_protocols {
        let selected = expand_protocols(&protocols, max_ports)?;
        excluded = excluded.saturating_add(selected.excluded);
        endpoints.extend(
            selected
                .values
                .into_iter()
                .map(|protocol| probe::Endpoint::Ip { protocol }),
        );
    }
    let plan = Plan::new(endpoints, neighbor)?;
    let options = match kind {
        Kind::Before { unresponsive } => Options::Before { plan, unresponsive },
        Kind::Only => Options::Only(plan),
    };
    Ok(DiscoveryPrepared { options, excluded })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Port {
    transport: PortTransport,
    number: u16,
}

impl Port {
    fn slot(self) -> (usize, usize, u64) {
        let transport = match self.transport {
            PortTransport::Tcp => 0,
            PortTransport::Udp => 1,
            PortTransport::Sctp => 2,
        };
        let number = usize::from(self.number);
        (transport, number / 64, 1 << (number % 64))
    }

    fn endpoint(self) -> probe::Endpoint {
        match self.transport {
            PortTransport::Tcp => probe::Endpoint::Tcp { port: self.number },
            PortTransport::Udp => probe::Endpoint::Udp { port: self.number },
            PortTransport::Sctp => probe::Endpoint::Sctp { port: self.number },
        }
    }
}

struct SeenPorts([Box<[u64; 1024]>; 3]);

impl Default for SeenPorts {
    fn default() -> Self {
        Self([
            Box::new([0; 1024]),
            Box::new([0; 1024]),
            Box::new([0; 1024]),
        ])
    }
}

#[derive(Default)]
struct SeenProtocols([u64; 4]);

trait Seen<T>: Default {
    fn insert(&mut self, value: T) -> bool;
    fn contains(&self, value: T) -> bool;
}

impl Seen<Port> for SeenPorts {
    fn insert(&mut self, value: Port) -> bool {
        let (transport, word, bit) = value.slot();
        let fresh = self.0[transport][word] & bit == 0;
        self.0[transport][word] |= bit;
        fresh
    }

    fn contains(&self, value: Port) -> bool {
        let (transport, word, bit) = value.slot();
        self.0[transport][word] & bit != 0
    }
}

impl Seen<u8> for SeenProtocols {
    fn insert(&mut self, value: u8) -> bool {
        let (word, bit) = protocol_slot(value);
        let fresh = self.0[word] & bit == 0;
        self.0[word] |= bit;
        fresh
    }

    fn contains(&self, value: u8) -> bool {
        self.0[usize::from(value) / 64] & (1_u64 << (value % 64)) != 0
    }
}

fn protocol_slot(value: u8) -> (usize, u64) {
    (usize::from(value) / 64, 1_u64 << (value % 64))
}

struct Expanded<T> {
    values: Vec<T>,
    excluded: usize,
}

fn expand_unique<S, T: Copy, M: Seen<T>>(
    include: &[S],
    exclude: &[S],
    expand: &impl Fn(&S, &mut dyn FnMut(T)) -> Result<(), Error>,
    max_ports: usize,
    empty: &'static str,
    excluded_empty: &'static str,
) -> Result<Expanded<T>, Error> {
    let mut excluded = M::default();
    for term in exclude {
        expand(term, &mut |value| {
            excluded.insert(value);
        })?;
    }
    let mut seen = M::default();
    let mut values = Vec::new();
    let mut removed = 0usize;
    for term in include {
        expand(term, &mut |value| {
            if !seen.insert(value) {
                return;
            }
            if excluded.contains(value) {
                removed += 1;
            } else {
                values.push(value);
            }
        })?;
    }
    if values.is_empty() {
        return Err(invalid(if removed == 0 { empty } else { excluded_empty }));
    }
    if values.len() > max_ports {
        return Err(Error::InvalidLimit {
            field: "ports",
            value: u64::try_from(values.len()).unwrap_or(u64::MAX),
            reason: format!("exceeds max_ports={max_ports}"),
        });
    }
    Ok(Expanded {
        values,
        excluded: removed,
    })
}

struct PortExpansion {
    values: Vec<Port>,
    excluded: usize,
    excluded_tcp: [u64; 1024],
}

fn expand_ports(
    selection: &PortSelection,
    catalog: &Catalog,
    max_ports: usize,
) -> Result<PortExpansion, Error> {
    let mut excluded = SeenPorts::default();
    for term in &selection.exclude {
        expand_term(term, &selection.transports, catalog, &mut |port| {
            excluded.insert(port);
        })?;
    }
    let mut seen = SeenPorts::default();
    let mut values = Vec::new();
    let mut removed = 0usize;
    let mut excluded_tcp = [0_u64; 1024];
    for term in &selection.include {
        expand_term(term, &selection.transports, catalog, &mut |port| {
            if !seen.insert(port) {
                return;
            }
            if excluded.contains(port) {
                removed += 1;
                if port.transport == PortTransport::Tcp {
                    let (_, word, bit) = port.slot();
                    excluded_tcp[word] |= bit;
                }
            } else {
                values.push(port);
            }
        })?;
    }
    if values.is_empty() {
        return Err(invalid(if removed == 0 {
            "TCP and UDP scans require at least one destination port"
        } else {
            "port exclusions removed every selected port"
        }));
    }
    if values.len() > max_ports {
        return Err(Error::InvalidLimit {
            field: "ports",
            value: u64::try_from(values.len()).unwrap_or(u64::MAX),
            reason: format!("exceeds max_ports={max_ports}"),
        });
    }
    Ok(PortExpansion {
        values,
        excluded: removed,
        excluded_tcp,
    })
}

fn expand_term(
    term: &Term,
    transports: &[PortTransport],
    catalog: &Catalog,
    visit: &mut dyn FnMut(Port),
) -> Result<(), Error> {
    let applies: Vec<PortTransport> = match term.transport {
        Some(transport) if transports.contains(&transport) => vec![transport],
        Some(transport) => {
            return Err(invalid(format!(
                "port term for {transport} needs {transport} among the scan transports"
            )));
        }
        None => transports.to_vec(),
    };
    match &term.selector {
        Selector::Ports(PortSpec::Single(port)) => {
            reject_zero_sctp(*port, &applies)?;
            for transport in applies {
                visit(Port {
                    transport,
                    number: *port,
                });
            }
        }
        Selector::Ports(PortSpec::RangeInclusive { start, end }) => {
            let spec = PortSpec::new(*start, *end)?;
            let PortSpec::RangeInclusive { start, end } = spec else {
                unreachable!()
            };
            reject_zero_sctp(start, &applies)?;
            for number in start..=end {
                for transport in &applies {
                    visit(Port {
                        transport: *transport,
                        number,
                    });
                }
            }
        }
        Selector::Name(name) => {
            let mut matched = false;
            for transport in &applies {
                let found = catalog_transport((*transport).into())
                    .and_then(|catalog_transport| catalog.named(catalog_transport, name));
                if let Some(entry) = found {
                    visit(Port {
                        transport: *transport,
                        number: entry.port,
                    });
                    matched = true;
                }
            }
            if !matched {
                return Err(invalid(format!(
                    "port name {name:?} is not in catalog {} for {}",
                    catalog.version,
                    transport_list(&applies)
                )));
            }
        }
        Selector::Preset(name) => {
            let preset = catalog.preset(name).ok_or_else(|| {
                invalid(format!(
                    "port preset {name:?} is not in catalog {}",
                    catalog.version
                ))
            })?;
            let mut matched = false;
            for transport in &applies {
                for (member_transport, member) in
                    preset.members().filter(|(member_transport, _)| {
                        catalog_transport((*transport).into()) == Some(*member_transport)
                    })
                {
                    let entry = catalog.named(member_transport, member).ok_or_else(|| {
                        invalid(format!(
                            "port preset {name:?} member {transport}/{member} is not in catalog {}",
                            catalog.version
                        ))
                    })?;
                    visit(Port {
                        transport: *transport,
                        number: entry.port,
                    });
                    matched = true;
                }
            }
            if !matched {
                return Err(invalid(format!(
                    "port preset {name:?} has no {} members",
                    transport_list(&applies)
                )));
            }
        }
    }
    Ok(())
}

fn expand_protocols(
    selection: &IpProtocolSelection,
    max_ports: usize,
) -> Result<Expanded<u8>, Error> {
    check_term_count(&selection.include, &selection.exclude, "ip_protocol terms")?;
    let (include, exclude) = (&selection.include, &selection.exclude);
    expand_unique::<_, _, SeenProtocols>(
        include,
        exclude,
        &|spec, visit| {
            for value in spec.values() {
                if let IpProtocolSpec::RangeInclusive { start, end } = *spec {
                    IpProtocolSpec::new(start, end)?;
                }
                visit(value);
            }
            Ok(())
        },
        max_ports,
        "IP-protocol scans require at least one IP protocol number",
        "IP-protocol exclusions removed every selected IP protocol",
    )
}

fn check_term_count<T>(include: &[T], exclude: &[T], field: &'static str) -> Result<(), Error> {
    let terms = include.len().saturating_add(exclude.len());
    if terms > MAX_PORT_TERMS {
        return Err(Error::InvalidLimit {
            field,
            value: u64::try_from(terms).unwrap_or(u64::MAX),
            reason: format!("exceeds {MAX_PORT_TERMS}"),
        });
    }
    Ok(())
}

fn reject_zero_sctp(port: u16, transports: &[PortTransport]) -> Result<(), Error> {
    if port == 0 && transports.contains(&PortTransport::Sctp) {
        return Err(invalid("SCTP scans require a non-zero destination port"));
    }
    Ok(())
}

fn push_unique(endpoints: &mut Vec<probe::Endpoint>, endpoint: probe::Endpoint) {
    if !endpoints.contains(&endpoint) {
        endpoints.push(endpoint);
    }
}

fn transport_list(transports: &[PortTransport]) -> String {
    transports
        .iter()
        .map(|transport| transport.as_str())
        .collect::<Vec<_>>()
        .join(" or ")
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidPort {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
