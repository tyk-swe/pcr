// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured traceroute output.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic as PacketDiagnostic;

use super::contract::Error;
use super::envelope::Stats;
use super::frame::{Captured, Timestamp};

pub use crate::traceroute::{Completion, ProbeStatus, ResponseKind};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub sequence: u64,
    pub hop_limit: u8,
    pub attempt: u32,
    pub strategy: String,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub status: ProbeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_kind: Option<ResponseKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder: Option<IpAddr>,
    pub sent_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<Captured>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Hop {
    pub hop_limit: u8,
    pub probes: Vec<Probe>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Undecoded {
    pub hop_limit: u8,
    pub frame: Captured,
}

/// Aggregate result of `traceroute`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub hops: Vec<Hop>,
    pub undecoded: Vec<Undecoded>,
    pub completion: Completion,
}

impl Result {
    pub fn try_from_traceroute(
        result: crate::traceroute::Result,
    ) -> std::result::Result<(Self, Vec<PacketDiagnostic>, Stats), Error> {
        let crate::traceroute::Result {
            target,
            resolved_addresses,
            destination,
            strategy,
            destination_port,
            hops,
            undecoded,
            completion,
            diagnostics,
            stats,
        } = result;
        let hop_outputs = hops
            .into_iter()
            .map(|hop| {
                let probe_outputs = hop
                    .probes
                    .into_iter()
                    .map(try_from_probe)
                    .collect::<std::result::Result<Vec<_>, Error>>()?;
                Ok(Hop {
                    hop_limit: hop.hop_limit,
                    probes: probe_outputs,
                })
            })
            .collect::<std::result::Result<Vec<_>, Error>>()?;
        let undecoded_outputs = undecoded
            .into_iter()
            .map(|evidence| {
                Ok(Undecoded {
                    hop_limit: evidence.hop_limit,
                    frame: Captured::try_from_frame(evidence.frame)?,
                })
            })
            .collect::<std::result::Result<Vec<_>, Error>>()?;
        Ok((
            Self {
                target,
                resolved_addresses,
                destination,
                strategy: strategy.to_string(),
                destination_port,
                hops: hop_outputs,
                undecoded: undecoded_outputs,
                completion,
            },
            diagnostics,
            stats.into(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Probe {
        target: String,
        probe: Probe,
    },
    Undecoded {
        hop_limit: u8,
        frame: Captured,
    },
    Diagnostic,
    Complete {
        target: String,
        resolved_addresses: Vec<IpAddr>,
        destination: IpAddr,
        strategy: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_port: Option<u16>,
        completion: Completion,
    },
}

impl Event {
    pub fn try_from_traceroute(
        event: crate::traceroute::Event,
    ) -> std::result::Result<(Self, Vec<PacketDiagnostic>), Error> {
        let (event, diagnostics) = match event {
            crate::traceroute::Event::Probe { target, probe } => (
                Self::Probe {
                    target: target.to_string(),
                    probe: try_from_probe(probe)?,
                },
                Vec::new(),
            ),
            crate::traceroute::Event::Undecoded(evidence) => (
                Self::Undecoded {
                    hop_limit: evidence.hop_limit,
                    frame: Captured::try_from_frame(evidence.frame)?,
                },
                Vec::new(),
            ),
            crate::traceroute::Event::Diagnostic(diagnostic) => {
                (Self::Diagnostic, vec![diagnostic])
            }
        };
        Ok((event, diagnostics))
    }

    pub fn complete_from_traceroute(
        summary: crate::traceroute::Summary,
    ) -> (Self, Vec<PacketDiagnostic>, Stats) {
        (
            Self::Complete {
                target: summary.target,
                resolved_addresses: summary.resolved_addresses,
                destination: summary.destination,
                strategy: summary.strategy.to_string(),
                destination_port: summary.destination_port,
                completion: summary.completion,
            },
            summary.diagnostics,
            summary.stats.into(),
        )
    }
}

fn try_from_probe(probe: crate::traceroute::ProbeEvidence) -> std::result::Result<Probe, Error> {
    Ok(Probe {
        sequence: probe.sequence,
        hop_limit: probe.hop_limit,
        attempt: probe.attempt,
        strategy: probe.strategy.to_string(),
        destination: probe.destination,
        destination_port: probe.destination_port,
        status: probe.status,
        response_kind: probe.response_kind,
        responder: probe.responder,
        sent_at: probe.sent_at.try_into()?,
        received_at: probe.received_at.map(Timestamp::try_from).transpose()?,
        latency: probe.latency,
        frame: probe.response.map(Captured::try_from_frame).transpose()?,
        reason: probe.reason,
    })
}
