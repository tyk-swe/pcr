// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contract for the `send` command.

use packetcraftr_client::send::Report as SendReport;
use packetcraftr_net::route::Materialized as DomainMaterializedRoute;
use packetcraftr_packet::diagnostic::Diagnostic;
use serde::Serialize;

use crate::output::contract::OutputContractError;
use crate::output::envelope::{CaptureStats, OperationStats};
use crate::output::frame::{FrameOutput, WireFrameOutput};
use crate::output::network::model::PlannedRouteOutput;

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
    pub captured: Vec<FrameOutput>,
    pub evidence_truncated: bool,
    pub capture_statistics: CaptureStats,
}

impl MaterializedRouteOutput {
    pub fn try_from_route(
        route: DomainMaterializedRoute,
    ) -> std::result::Result<Self, OutputContractError> {
        let neighbor = route
            .neighbor_resolution
            .map(|resolution| {
                let captured = resolution
                    .captured
                    .into_iter()
                    .map(FrameOutput::try_from_frame)
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(NeighborEvidenceOutput {
                    mac_address: resolution.mac_address.to_string(),
                    attempts: resolution.attempts,
                    cache_hit: resolution.cache_hit,
                    captured,
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
    pub frame: WireFrameOutput,
    pub route: MaterializedRouteOutput,
}

impl SendCommandResult {
    pub fn try_from_report(
        report: SendReport,
    ) -> std::result::Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let SendReport {
            built,
            route,
            wire_bytes,
            stats,
        } = report;
        let frame = WireFrameOutput::new(wire_bytes);
        Ok((
            Self {
                frame,
                route: MaterializedRouteOutput::try_from_route(route)?,
            },
            built.diagnostics,
            stats.into(),
        ))
    }
}

pub use MaterializedRouteOutput as MaterializedRoute;
pub use NeighborEvidenceOutput as NeighborEvidence;
pub use SendCommandResult as Result;
