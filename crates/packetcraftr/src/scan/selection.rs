// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed port selections: numbers, ranges, catalog names, and presets per
//! transport, with exclusions applied after expansion and before planning.

use super::Error;
use super::catalog::{Catalog, catalog_transport};
use super::request::PortSpec;
use crate::probe::{ProbeEndpoint, Transport};

/// Bounds the expansion work one selection can request.
pub const MAX_PORT_TERMS: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    Ports(PortSpec),
    /// A catalog entry name; a hint for a port number, not a service.
    Name(String),
    Preset(String),
}

/// One selection term; `transport: None` applies it to every selected
/// transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term {
    pub transport: Option<Transport>,
    pub selector: Selector,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortSelection {
    /// TCP and/or UDP, in the order unqualified terms expand.
    pub transports: Vec<Transport>,
    pub include: Vec<Term>,
    pub exclude: Vec<Term>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selected {
    pub endpoints: Vec<ProbeEndpoint>,
    /// Distinct expanded endpoints removed by exclusions.
    pub excluded: usize,
}

/// Expands `include` in first-seen term order (transports in selection order
/// within a term), removes every endpoint `exclude` expands to, then bounds
/// the remainder by `max_ports`.
pub fn select_endpoints(
    selection: &PortSelection,
    catalog: &Catalog,
    max_ports: usize,
) -> Result<Selected, Error> {
    let PortSelection {
        transports,
        include,
        exclude,
    } = selection;
    if transports.is_empty() || transports.contains(&Transport::Icmp) {
        return Err(invalid("port selections need TCP and/or UDP transports"));
    }
    let terms = include.len().saturating_add(exclude.len());
    if terms > MAX_PORT_TERMS {
        return Err(Error::InvalidLimit {
            field: "port terms",
            value: u64::try_from(terms).unwrap_or(u64::MAX),
            reason: format!("exceeds {MAX_PORT_TERMS}"),
        });
    }
    let mut excluded = Seen::default();
    for term in exclude {
        expand(term, transports, catalog, |endpoint| {
            excluded.insert(endpoint);
        })?;
    }
    let mut seen = Seen::default();
    let mut endpoints = Vec::new();
    let mut removed = 0usize;
    for term in include {
        expand(term, transports, catalog, |endpoint| {
            if !seen.insert(endpoint) {
                return;
            }
            if excluded.contains(endpoint) {
                removed += 1;
            } else {
                endpoints.push(endpoint);
            }
        })?;
    }
    if endpoints.is_empty() {
        return Err(invalid(if removed == 0 {
            "TCP and UDP scans require at least one destination port"
        } else {
            "port exclusions removed every selected port"
        }));
    }
    if endpoints.len() > max_ports {
        return Err(Error::InvalidLimit {
            field: "ports",
            value: u64::try_from(endpoints.len()).unwrap_or(u64::MAX),
            reason: format!("exceeds max_ports={max_ports}"),
        });
    }
    Ok(Selected {
        endpoints,
        excluded: removed,
    })
}

fn expand(
    term: &Term,
    transports: &[Transport],
    catalog: &Catalog,
    mut visit: impl FnMut(ProbeEndpoint),
) -> Result<(), Error> {
    let applies: Vec<Transport> = match term.transport {
        Some(transport) if transports.contains(&transport) => vec![transport],
        Some(transport) => {
            return Err(invalid(format!(
                "port term for {transport} needs {transport} among the scan transports"
            )));
        }
        None => transports.to_vec(),
    };
    match &term.selector {
        Selector::Ports(spec) => {
            let (start, end) = match *spec {
                PortSpec::Single(port) => (port, port),
                PortSpec::RangeInclusive { start, end } => (start, end),
            };
            if start > end {
                return Err(invalid(format!("port range {start}-{end} is descending")));
            }
            for port in start..=end {
                for transport in &applies {
                    visit(endpoint(*transport, port));
                }
            }
        }
        Selector::Name(name) => {
            let mut matched = false;
            for transport in &applies {
                let found = catalog_transport(*transport)
                    .and_then(|catalog_transport| catalog.named(catalog_transport, name));
                if let Some(entry) = found {
                    visit(endpoint(*transport, entry.port));
                    matched = true;
                }
            }
            if !matched {
                return Err(invalid(format!(
                    "port name {name:?} is not in catalog {} for {}",
                    catalog.version,
                    list(&applies)
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
            for (member_transport, member) in preset.members() {
                let Some(transport) = applies
                    .iter()
                    .copied()
                    .find(|transport| catalog_transport(*transport) == Some(member_transport))
                else {
                    continue;
                };
                let entry = catalog.named(member_transport, member).ok_or_else(|| {
                    invalid(format!(
                        "port preset {name:?} member {transport}/{member} is not in catalog {}",
                        catalog.version
                    ))
                })?;
                visit(endpoint(transport, entry.port));
                matched = true;
            }
            if !matched {
                return Err(invalid(format!(
                    "port preset {name:?} has no {} members",
                    list(&applies)
                )));
            }
        }
    }
    Ok(())
}

fn endpoint(transport: Transport, port: u16) -> ProbeEndpoint {
    match transport {
        Transport::Tcp => ProbeEndpoint::Tcp { port },
        Transport::Udp => ProbeEndpoint::Udp { port },
        Transport::Icmp => unreachable!("port selections are validated to TCP and UDP"),
    }
}

fn list(transports: &[Transport]) -> String {
    transports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" or ")
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidPort {
        message: message.into(),
    }
}

/// One bit per (transport, port), so expansion memory stays fixed.
struct Seen([Box<[u64; 1024]>; 2]);

impl Default for Seen {
    fn default() -> Self {
        Self([Box::new([0; 1024]), Box::new([0; 1024])])
    }
}

impl Seen {
    fn slot(endpoint: ProbeEndpoint) -> (usize, usize, u64) {
        let (table, port) = match endpoint {
            ProbeEndpoint::Tcp { port } => (0, port),
            ProbeEndpoint::Udp { port } => (1, port),
            ProbeEndpoint::Icmp => unreachable!("port selections expand only TCP and UDP"),
        };
        let port = usize::from(port);
        (table, port / 64, 1 << (port % 64))
    }

    /// Returns whether the endpoint was not yet present.
    fn insert(&mut self, endpoint: ProbeEndpoint) -> bool {
        let (table, word, bit) = Self::slot(endpoint);
        let fresh = self.0[table][word] & bit == 0;
        self.0[table][word] |= bit;
        fresh
    }

    fn contains(&self, endpoint: ProbeEndpoint) -> bool {
        let (table, word, bit) = Self::slot(endpoint);
        self.0[table][word] & bit != 0
    }
}

#[cfg(test)]
mod tests;
