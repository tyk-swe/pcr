// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use packetcraftr::probe::{ProbeEndpoint, Transport};
use packetcraftr::scan::{
    MAX_UDP_PAYLOAD_BYTES, discovery,
    profile::{self, UdpProfile},
};
use packetcraftr_core::document::udp_profiles::{self, MAX_PROFILE_BYTES};
use packetcraftr_core::error::{Classified, Kind};

use super::arguments;
use crate::errors::CliError;
use crate::input::{InputKind, manifest, read_bounded_file_allow_empty};

/// The requested transports in first-seen order. ICMP echo is portless and
/// cannot share a plan with port endpoints.
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
            "--transport icmp is portless and cannot be combined with tcp or udp",
        ));
    }
    Ok(transports)
}

/// The discovery stage the flags select, with the endpoints --exclude-ports
/// removed from it. Port probes take --discovery-ports through the scan's
/// catalog and --exclude-ports, so discovery never probes an excluded
/// endpoint; ICMP echo is the default probe.
pub(super) fn discovery_options(
    mode: Option<arguments::Discovery>,
    probes: &[arguments::DiscoveryProbe],
    ports: Vec<arguments::PortTerm>,
    exclude_ports: &[arguments::PortTerm],
    unresponsive: Option<arguments::UnresponsiveHosts>,
    max_ports: usize,
) -> Result<(discovery::Options, usize), CliError> {
    let Some(mode) = mode else {
        return Ok((discovery::Options::default(), 0));
    };
    let mut options = discovery::Options {
        mode: mode.into(),
        unresponsive: unresponsive.map_or_else(Default::default, Into::into),
        ..discovery::Options::default()
    };
    let probes = if probes.is_empty() && options.runs() {
        &[arguments::DiscoveryProbe::Icmp][..]
    } else {
        probes
    };
    let mut transports = Vec::new();
    for probe in probes {
        let transport = match probe {
            arguments::DiscoveryProbe::Neighbor => {
                options.neighbor = true;
                continue;
            }
            arguments::DiscoveryProbe::Icmp => Transport::Icmp,
            arguments::DiscoveryProbe::Tcp => Transport::Tcp,
            arguments::DiscoveryProbe::Udp => Transport::Udp,
        };
        if !transports.contains(&transport) {
            transports.push(transport);
        }
    }
    // ICMP echo is portless and leads; port probes follow in term order.
    if let Some(index) = transports
        .iter()
        .position(|transport| *transport == Transport::Icmp)
    {
        transports.remove(index);
        options.probes.push(ProbeEndpoint::Icmp);
    }
    if transports.is_empty() {
        if !ports.is_empty() {
            return Err(CliError::new(
                Kind::Usage,
                "--discovery-ports needs tcp or udp among --discovery-probes",
            ));
        }
        return Ok((options, 0));
    }
    if ports.is_empty() {
        return Err(CliError::new(
            Kind::Usage,
            "tcp and udp discovery probes need --discovery-ports",
        ));
    }
    // An exclusion prefixed with a transport discovery does not probe
    // applies only to the scan's endpoints.
    let exclude = exclude_ports
        .iter()
        .filter(|term| {
            term.0
                .transport
                .is_none_or(|transport| transports.contains(&transport))
        })
        .map(|term| term.0.clone())
        .collect();
    let selected = packetcraftr::scan::select_endpoints(
        &packetcraftr::scan::PortSelection {
            transports,
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
    options.probes.extend(selected.endpoints);
    Ok((options, selected.excluded))
}

pub(super) fn select_endpoints(
    transports: &[Transport],
    ports: Vec<arguments::PortTerm>,
    exclude_ports: Vec<arguments::PortTerm>,
    max_ports: usize,
) -> Result<packetcraftr::scan::Selected, CliError> {
    if transports == [Transport::Icmp] {
        if !ports.is_empty() || !exclude_ports.is_empty() {
            return Err(CliError::new(
                Kind::Usage,
                "--ports and --exclude-ports do not apply to portless ICMP echo scans",
            ));
        }
        return Ok(packetcraftr::scan::Selected {
            endpoints: vec![ProbeEndpoint::Icmp],
            excluded: 0,
        });
    }
    packetcraftr::scan::select_endpoints(
        &packetcraftr::scan::PortSelection {
            transports: transports.to_vec(),
            include: ports.into_iter().map(|term| term.0).collect(),
            exclude: exclude_ports.into_iter().map(|term| term.0).collect(),
        },
        packetcraftr::scan::catalog::bundled(),
        max_ports,
    )
    .map_err(CliError::classified)
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
