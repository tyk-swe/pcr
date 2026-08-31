// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contract for the `send` command.

use packetcraftr_core::diagnostic::Diagnostic;

use serde::Serialize;

use crate::output::contract::Error;
use crate::output::envelope::{CaptureStats, Stats};
use crate::output::frame::Captured;
use crate::output::frame::Wire;
use crate::output::network::Plan;

/// Serializable route materialization evidence retained by send-like commands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MaterializedRoute {
    pub plan: Plan,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neighbor: Option<NeighborEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NeighborEvidence {
    pub mac_address: String,
    pub attempts: u32,
    pub cache_hit: bool,
    pub captured: Vec<Captured>,
    pub evidence_truncated: bool,
    pub capture_statistics: CaptureStats,
}

impl MaterializedRoute {
    pub fn try_from_route(route: packetcraftr_netio::route::Materialized) -> Result<Self, Error> {
        let neighbor = route
            .neighbor_resolution
            .map(|resolution| {
                Ok(NeighborEvidence {
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
pub struct Report {
    pub frame: Wire,
    pub route: MaterializedRoute,
}

impl Report {
    pub fn try_from_report(
        report: crate::send::Report,
    ) -> Result<(Self, Vec<Diagnostic>, Stats), Error> {
        let crate::send::Report { sent, stats } = report;
        Ok((
            Self {
                frame: Wire::new(sent.wire_bytes().clone()),
                route: MaterializedRoute::try_from_route(sent.route().clone())?,
            },
            sent.built().diagnostics.clone(),
            stats.into(),
        ))
    }
}
