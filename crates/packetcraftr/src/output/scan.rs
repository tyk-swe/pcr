// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured scan output.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic as PacketDiagnostic;

use super::contract::Error;
use super::envelope::Stats;
use super::frame::{Captured, Timestamp};

pub use crate::scan::{Classification, ProbeStatus};

/// One canonical scan probe record used by aggregate and stream output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub sequence: u64,
    pub protocol: String,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub attempt: u32,
    pub status: ProbeStatus,
    pub classification: Classification,
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
pub struct Endpoint {
    pub address: IpAddr,
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub classification: Classification,
    pub probes: Vec<Probe>,
}

/// Aggregate result of `scan`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub endpoints: Vec<Endpoint>,
    pub undecoded: Vec<Captured>,
}

impl Result {
    pub fn try_from_scan(
        result: crate::scan::Result,
    ) -> std::result::Result<(Self, Vec<PacketDiagnostic>, Stats), Error> {
        let crate::scan::Result {
            target,
            resolved_addresses,
            endpoints,
            undecoded,
            diagnostics,
            stats,
        } = result;
        let endpoint_outputs = endpoints
            .into_iter()
            .map(|endpoint| {
                let probe_outputs = endpoint
                    .probes
                    .into_iter()
                    .map(try_from_probe)
                    .collect::<std::result::Result<Vec<_>, Error>>()?;
                Ok(Endpoint {
                    address: endpoint.address,
                    transport: endpoint.transport.to_string(),
                    port: endpoint.port,
                    classification: endpoint.classification,
                    probes: probe_outputs,
                })
            })
            .collect::<std::result::Result<Vec<_>, Error>>()?;
        Ok((
            Self {
                target,
                resolved_addresses,
                endpoints: endpoint_outputs,
                undecoded: Captured::try_from_frames(undecoded)?,
            },
            diagnostics,
            stats.into(),
        ))
    }
}

/// One independently useful event in structured scan streaming output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Probe {
        target: String,
        probe: Probe,
    },
    Undecoded {
        frame: Captured,
    },
    Diagnostic,
    Complete {
        target: String,
        resolved_addresses: Vec<IpAddr>,
    },
}

impl Event {
    pub fn try_from_scan(
        event: crate::scan::Event,
    ) -> std::result::Result<(Self, Vec<PacketDiagnostic>), Error> {
        let (event, diagnostics) = match event {
            crate::scan::Event::Probe { target, probe } => (
                Self::Probe {
                    target: target.to_string(),
                    probe: try_from_probe(probe)?,
                },
                Vec::new(),
            ),
            crate::scan::Event::Undecoded { frame } => (
                Self::Undecoded {
                    frame: Captured::try_from_frame(frame)?,
                },
                Vec::new(),
            ),
            crate::scan::Event::Diagnostic(diagnostic) => (Self::Diagnostic, vec![diagnostic]),
        };
        Ok((event, diagnostics))
    }

    pub fn complete_from_scan(
        summary: crate::scan::Summary,
    ) -> (Self, Vec<PacketDiagnostic>, Stats) {
        (
            Self::Complete {
                target: summary.target,
                resolved_addresses: summary.resolved_addresses,
            },
            summary.diagnostics,
            summary.stats.into(),
        )
    }
}

fn try_from_probe(evidence: crate::scan::ProbeEvidence) -> std::result::Result<Probe, Error> {
    let protocol = match (evidence.transport, evidence.address) {
        (crate::scan::Transport::Icmp, IpAddr::V4(_)) => "icmpv4",
        (crate::scan::Transport::Icmp, IpAddr::V6(_)) => "icmpv6",
        _ => evidence.transport.as_str(),
    };
    Ok(Probe {
        sequence: evidence.sequence,
        protocol: protocol.to_owned(),
        destination: evidence.address,
        destination_port: evidence.port,
        attempt: evidence.attempt,
        status: evidence.status,
        classification: evidence.classification,
        responder: evidence.responder,
        sent_at: evidence.sent_at.try_into()?,
        received_at: evidence.received_at.map(Timestamp::try_from).transpose()?,
        latency: evidence.latency,
        frame: evidence
            .response
            .map(Captured::try_from_frame)
            .transpose()?,
        reason: evidence.reason,
    })
}
