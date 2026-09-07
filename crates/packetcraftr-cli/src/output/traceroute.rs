// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured traceroute output.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic as PacketDiagnostic;

use super::contract::Error;
use super::frame::{Captured, Timestamp};
use packetcraftr::Stats;

use packetcraftr::traceroute::{Completion, ProbeStatus, ResponseKind, Strategy};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub sequence: u64,
    pub hop_limit: u8,
    pub attempt: u32,
    pub strategy: Strategy,
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
pub struct Report {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: Strategy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub hops: Vec<Hop>,
    pub undecoded: Vec<Undecoded>,
    pub completion: Completion,
}

impl Report {
    pub fn try_from_traceroute(
        result: packetcraftr::traceroute::Report,
    ) -> Result<(Self, Vec<PacketDiagnostic>, Stats), Error> {
        let packetcraftr::traceroute::Report {
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
                    .collect::<Result<Vec<_>, Error>>()?;
                Ok(Hop {
                    hop_limit: hop.hop_limit,
                    probes: probe_outputs,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let undecoded_outputs = undecoded
            .into_iter()
            .map(|evidence| {
                Ok(Undecoded {
                    hop_limit: evidence.hop_limit,
                    frame: Captured::try_from_frame(evidence.frame)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok((
            Self {
                target,
                resolved_addresses,
                destination,
                strategy,
                destination_port,
                hops: hop_outputs,
                undecoded: undecoded_outputs,
                completion,
            },
            diagnostics,
            stats,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Event {
    Probe {
        target: String,
        probe: Probe,
    },
    Undecoded {
        hop_limit: u8,
        frame: Captured,
    },
    Diagnostic {},
    Complete {
        target: String,
        resolved_addresses: Vec<IpAddr>,
        destination: IpAddr,
        strategy: Strategy,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_port: Option<u16>,
        completion: Completion,
    },
}

impl Event {
    pub fn try_from_traceroute(
        event: packetcraftr::traceroute::Event,
    ) -> Result<(Self, Vec<PacketDiagnostic>), Error> {
        let (event, diagnostics) = match event {
            packetcraftr::traceroute::Event::Probe { target, probe } => (
                Self::Probe {
                    target: target.to_string(),
                    probe: try_from_probe(probe)?,
                },
                Vec::new(),
            ),
            packetcraftr::traceroute::Event::Undecoded(evidence) => (
                Self::Undecoded {
                    hop_limit: evidence.hop_limit,
                    frame: Captured::try_from_frame(evidence.frame)?,
                },
                Vec::new(),
            ),
            packetcraftr::traceroute::Event::Diagnostic(diagnostic) => {
                (Self::Diagnostic {}, vec![diagnostic])
            }
        };
        Ok((event, diagnostics))
    }

    pub fn complete_from_traceroute(
        summary: packetcraftr::traceroute::Summary,
    ) -> (Self, Vec<PacketDiagnostic>, Stats) {
        (
            Self::Complete {
                target: summary.target,
                resolved_addresses: summary.resolved_addresses,
                destination: summary.destination,
                strategy: summary.strategy,
                destination_port: summary.destination_port,
                completion: summary.completion,
            },
            Vec::new(),
            summary.stats,
        )
    }
}

fn try_from_probe(probe: packetcraftr::traceroute::ProbeEvidence) -> Result<Probe, Error> {
    Ok(Probe {
        sequence: probe.sequence,
        hop_limit: probe.hop_limit,
        attempt: probe.attempt,
        strategy: probe.strategy,
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

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Probe { .. } => "probe",
            Self::Undecoded { .. } => "undecoded",
            Self::Diagnostic {} => "diagnostic",
            Self::Complete { .. } => "complete",
        }
    }
}
