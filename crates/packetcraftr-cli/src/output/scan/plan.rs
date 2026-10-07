// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! How a scan was planned, and the port inferences drawn from its attempts.

use serde::Serialize;

use packetcraftr::probe::Transport;
use packetcraftr::scan as library;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DataSet {
    pub name: &'static str,
    pub version: &'static str,
}

impl From<library::DataSet> for DataSet {
    fn from(data_set: library::DataSet) -> Self {
        Self {
            name: data_set.name,
            version: data_set.version,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Method {
    pub requested: &'static str,
    pub selected: &'static str,
    /// Why automatic selection chose `selected`; absent for explicit methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<library::method::Selection> for Method {
    fn from(selection: library::method::Selection) -> Self {
        Self {
            requested: selection.requested.as_str(),
            selected: selection.method.as_str(),
            reason: selection.reason,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CuratedPayloads {
    pub data_set: DataSet,
    /// Selected UDP ports probed with a curated payload.
    pub applied: Vec<u16>,
    /// Selected UDP ports where an operator profile replaced the curated one.
    pub overridden: Vec<u16>,
}

impl From<library::profile::curated::Merged> for CuratedPayloads {
    fn from(merged: library::profile::curated::Merged) -> Self {
        Self {
            data_set: library::profile::curated::data_set().into(),
            applied: merged.applied,
            overridden: merged.overridden,
        }
    }
}

/// Published once per scan, beside its results.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub method: Method,
    /// The catalog behind port names, presets, and `port_hint`s.
    pub port_catalog: DataSet,
    /// Distinct expanded endpoints `--exclude-ports` removed before planning.
    pub excluded_endpoints: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curated_udp_payloads: Option<CuratedPayloads>,
}

/// The port endpoints a scan would probe on every target, after exclusions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Ports {
    pub port_catalog: DataSet,
    pub excluded_endpoints: usize,
    pub endpoints: Vec<PortEndpoint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PortEndpoint {
    pub transport: Transport,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_hint: Option<&'static str>,
}

impl From<&library::Selected> for Ports {
    fn from(selected: &library::Selected) -> Self {
        Self {
            port_catalog: library::catalog::data_set().into(),
            excluded_endpoints: selected.excluded,
            endpoints: selected
                .endpoints
                .iter()
                .filter_map(|endpoint| {
                    let transport = endpoint.transport();
                    endpoint.port().map(|port| PortEndpoint {
                        transport,
                        port,
                        port_hint: library::catalog::hint(transport, port),
                    })
                })
                .collect(),
        }
    }
}

/// A scan-dependent conclusion about one port endpoint. Every attempt
/// sequence appears in exactly one list; the attempts stay in `probes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Inference {
    /// Absent when only operational failures were observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<&'static str>,
    pub rule: &'static str,
    pub supporting: Vec<u64>,
    pub conflicting: Vec<u64>,
    pub unanswered: Vec<u64>,
    pub failed: Vec<u64>,
}

impl From<library::Inference> for Inference {
    fn from(inference: library::Inference) -> Self {
        Self {
            state: inference.state.map(library::State::as_str),
            rule: inference.rule.as_str(),
            supporting: inference.supporting,
            conflicting: inference.conflicting,
            unanswered: inference.unanswered,
            failed: inference.failed,
        }
    }
}
