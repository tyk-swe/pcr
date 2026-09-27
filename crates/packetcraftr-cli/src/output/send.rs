// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use crate::output::capture::Stats as CaptureStats;
use crate::output::contract::Error;
use crate::output::envelope::Published;
use crate::output::frame::Captured;
use crate::output::frame::Wire;
use crate::output::network::Plan;

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

impl TryFrom<packetcraftr::route::Materialized> for MaterializedRoute {
    type Error = Error;

    fn try_from(route: packetcraftr::route::Materialized) -> Result<Self, Error> {
        let neighbor = route
            .neighbor_resolution
            .map(|resolution| {
                Ok::<_, Error>(NeighborEvidence {
                    mac_address: resolution.mac_address.to_string(),
                    attempts: resolution.attempts,
                    cache_hit: resolution.cache_hit,
                    captured: resolution
                        .captured
                        .into_iter()
                        .map(Captured::try_from)
                        .collect::<Result<_, _>>()?,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SentFrame {
    pub pass: u32,
    pub index: u64,
    pub frame: Wire,
    pub route: MaterializedRoute,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub frames: Vec<SentFrame>,
    pub passes_completed: u32,
}

impl TryFrom<packetcraftr::send::Aggregate> for Published<Report> {
    type Error = Error;

    fn try_from(report: packetcraftr::send::Aggregate) -> Result<Self, Error> {
        let packetcraftr::send::Aggregate {
            sent,
            passes_completed,
            stats,
        } = report;
        let mut diagnostics = Vec::new();
        let mut frames = Vec::with_capacity(sent.len());
        for sent_frame in sent {
            let packetcraftr::send::SentFrame {
                pass,
                index,
                packet,
            } = sent_frame;
            for diagnostic in &packet.built().diagnostics {
                packetcraftr_core::diagnostic::push_once(&mut diagnostics, diagnostic.clone());
            }
            frames.push(SentFrame {
                pass,
                index,
                frame: packet.wire_bytes().clone().into(),
                route: packet.route().clone().try_into()?,
            });
        }
        Ok(Self::new(
            Report {
                frames,
                passes_completed,
            },
            diagnostics,
        )
        .with_stats(stats))
    }
}
