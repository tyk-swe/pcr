// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;
use std::net::IpAddr;

use super::{Scope, plan::Ports};
use crate::input::manifest::Declaration;
use crate::output::stream::StreamRecord;
use packetcraftr::target::plan;

const METHOD: &str = "target_list";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Origin {
    pub index: u32,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

impl Origin {
    pub(crate) fn new(index: u32, declaration: &Declaration) -> Self {
        Self {
            index,
            source: declaration.source.to_string(),
            line: declaration.line,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Target {
    method: &'static str,
    pub address: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    pub origins: Vec<Origin>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TargetEvent {
    #[serde(flatten)]
    target: Target,
}

impl From<&Target> for TargetEvent {
    fn from(target: &Target) -> Self {
        Self {
            target: target.clone(),
        }
    }
}

impl StreamRecord for TargetEvent {
    fn event_name(&self) -> &'static str {
        "target"
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    method: &'static str,
    pub target: String,
    pub resolution_performed: bool,
    pub targets: Vec<Target>,
    pub duplicates: Vec<Origin>,
    /// Present when port terms were given: the endpoints a scan of these
    /// targets would probe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Ports>,
}

impl Report {
    pub(crate) fn new(
        report: plan::Report,
        declarations: &[Declaration],
        ports: Option<Ports>,
    ) -> Self {
        Self {
            method: METHOD,
            target: report.declared,
            resolution_performed: report.resolution_performed,
            targets: report
                .targets
                .into_iter()
                .map(|target| Target {
                    method: METHOD,
                    address: target.selected.address,
                    scope: target.selected.scope.as_ref().map(Scope::from),
                    origins: target
                        .declarations
                        .iter()
                        .filter_map(|index| {
                            declarations
                                .get(*index as usize)
                                .map(|declaration| Origin::new(*index, declaration))
                        })
                        .collect(),
                })
                .collect(),
            duplicates: report
                .duplicates
                .iter()
                .filter_map(|index| {
                    declarations
                        .get(*index as usize)
                        .map(|declaration| Origin::new(*index, declaration))
                })
                .collect(),
            ports,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Complete {
    method: &'static str,
    pub target: String,
    pub resolution_performed: bool,
    pub count: usize,
    pub duplicates: Vec<Origin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Ports>,
}

impl From<Report> for Complete {
    fn from(report: Report) -> Self {
        Self {
            method: METHOD,
            target: report.target,
            resolution_performed: report.resolution_performed,
            count: report.targets.len(),
            duplicates: report.duplicates,
            ports: report.ports,
        }
    }
}

impl StreamRecord for Complete {
    fn event_name(&self) -> &'static str {
        "complete"
    }
}
