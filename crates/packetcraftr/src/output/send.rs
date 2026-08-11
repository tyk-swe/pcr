// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contract for the `send` command.

use packetcraftr_live::send::Report as SendReport;
use packetcraftr_network::route::Materialized as DomainMaterializedRoute;
use packetcraftr_packet::diagnostic::Diagnostic;
use serde::Serialize;

use crate::output::contract::Error;
use crate::output::envelope::{CaptureStats, Stats};
use crate::output::frame::Captured;
use crate::output::network::PlannedRouteOutput;

pub use crate::output::frame::{Captured as Frame, Wire};

/// Serializable route materialization evidence retained by send-like commands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MaterializedRouteOutput {
    pub plan: PlannedRouteOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neighbor: Option<NeighborEvidenceOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NeighborEvidenceOutput {
    pub mac_address: String,
    pub attempts: u32,
    pub cache_hit: bool,
    pub captured: Vec<Captured>,
    pub evidence_truncated: bool,
    pub capture_statistics: CaptureStats,
}

impl MaterializedRouteOutput {
    pub fn try_from_route(route: DomainMaterializedRoute) -> std::result::Result<Self, Error> {
        let neighbor = route
            .neighbor_resolution
            .map(|resolution| {
                Ok(NeighborEvidenceOutput {
                    mac_address: resolution.mac_address.to_string(),
                    attempts: resolution.attempts,
                    cache_hit: resolution.cache_hit,
                    captured: Captured::try_from_frames(resolution.captured)?,
                    evidence_truncated: resolution.evidence_truncated,
                    capture_statistics: resolution.capture_statistics.into(),
                })
            })
            .transpose()?;
        Ok(Self {
            plan: route.plan.into(),
            neighbor,
        })
    }
}

/// Aggregate result of `send`; operation statistics live in the envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SendCommandResult {
    pub frame: Wire,
    pub route: MaterializedRouteOutput,
}

impl SendCommandResult {
    pub fn try_from_report(
        report: SendReport,
    ) -> std::result::Result<(Self, Vec<Diagnostic>, Stats), Error> {
        let SendReport { sent, stats } = report;
        Ok((
            Self {
                frame: Wire::new(sent.wire_bytes().clone()),
                route: MaterializedRouteOutput::try_from_route(sent.route().clone())?,
            },
            sent.built().diagnostics.clone(),
            stats.into(),
        ))
    }
}

pub use MaterializedRouteOutput as MaterializedRoute;
pub use NeighborEvidenceOutput as NeighborEvidence;
pub use SendCommandResult as Result;
