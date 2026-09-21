// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured scan output.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic as PacketDiagnostic;

use super::contract::Error;
use super::frame::{Captured, Timestamp};
use packetcraftr::Stats;

use packetcraftr::probe::{ProbeStatus, Transport};
use packetcraftr::scan::{Classification, ClassificationCounts};

/// The wire protocol one probe was sent over. `packetcraftr::probe::Transport::Icmp` splits by
/// address family here because the output contract names the two ICMP protocols
/// separately; this enum is the only declaration of that vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmpv4,
    Icmpv6,
}

/// One canonical scan probe record used by aggregate and stream output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub sequence: u64,
    pub protocol: Protocol,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<packetcraftr::scan::profile::Evidence>,
}

/// Final per-endpoint rollup: the winning classification and every probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub transport: Transport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub classification: Classification,
    pub probes: Vec<Probe>,
}

/// Aggregate result of `scan`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub planned_duration: Duration,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub endpoints: Vec<Endpoint>,
    pub undecoded: Vec<Captured>,
    pub rtt: packetcraftr::scan::Rtt,
}

impl Report {
    pub fn try_from_scan(
        result: packetcraftr::scan::Report,
    ) -> Result<(Self, Vec<PacketDiagnostic>, Stats), Error> {
        let packetcraftr::scan::Report {
            planned_duration,
            target,
            resolved_addresses,
            endpoints,
            undecoded,
            diagnostics,
            stats,
            rtt,
        } = result;
        let endpoint_outputs = endpoints
            .into_iter()
            .map(|endpoint| {
                let probe_outputs = endpoint
                    .probes
                    .into_iter()
                    .map(try_from_probe)
                    .collect::<Result<Vec<_>, Error>>()?;
                Ok(Endpoint {
                    address: endpoint.address,
                    transport: endpoint.transport,
                    port: endpoint.port,
                    classification: endpoint.classification,
                    probes: probe_outputs,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok((
            Self {
                planned_duration,
                target,
                resolved_addresses,
                endpoints: endpoint_outputs,
                undecoded: Captured::try_from_frames(undecoded)?,
                rtt,
            },
            diagnostics,
            stats,
        ))
    }
}

/// A transmitted probe packet with its destination and timing evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Sent {
    pub sequence: u64,
    pub protocol: Protocol,
    pub destination: IpAddr,
    pub destination_port: Option<u16>,
    pub attempt: u32,
    pub sent_at: Timestamp,
    pub udp_profile: Option<String>,
    pub frame: super::frame::Wire,
    pub route: super::send::MaterializedRoute,
}
impl Sent {
    pub fn try_from_sent(value: packetcraftr::scan::SentProbe) -> Result<Self, Error> {
        let probe = value.probe;
        let sent = value.sent;
        let protocol = match (probe.endpoint.transport(), probe.address) {
            (Transport::Tcp, _) => Protocol::Tcp,
            (Transport::Udp, _) => Protocol::Udp,
            (Transport::Icmp, IpAddr::V4(_)) => Protocol::Icmpv4,
            (Transport::Icmp, IpAddr::V6(_)) => Protocol::Icmpv6,
        };
        Ok(Self {
            sequence: probe.sequence,
            udp_profile: probe
                .udp_profile
                .as_ref()
                .map(|profile| profile.name().to_owned()),
            protocol,
            destination: probe.address,
            destination_port: probe.endpoint.port(),
            attempt: probe.attempt,
            sent_at: Timestamp::try_from(sent.timing().freshness_marker().wall_clock())?,
            frame: super::frame::Wire::new(sent.wire_bytes().clone()),
            route: super::send::MaterializedRoute::try_from_route(sent.route().clone())?,
        })
    }
}

/// One independently useful event in structured scan streaming output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Event {
    Sent {
        sent: Sent,
    },
    Probe {
        target: String,
        probe: Probe,
    },
    Undecoded {
        frame: Captured,
    },
    Diagnostic {},
    Complete {
        planned_duration: Duration,
        target: String,
        resolved_addresses: Vec<IpAddr>,
        counts: ClassificationCounts,
        rtt: packetcraftr::scan::Rtt,
    },
}

impl Event {
    pub fn try_from_scan(
        event: packetcraftr::scan::Event,
    ) -> Result<(Self, Vec<PacketDiagnostic>), Error> {
        let (event, diagnostics) = match event {
            packetcraftr::scan::Event::Sent(sent) => (
                Self::Sent {
                    sent: Sent::try_from_sent(sent)?,
                },
                Vec::new(),
            ),
            packetcraftr::scan::Event::Probe { target, probe } => (
                Self::Probe {
                    target: target.to_string(),
                    probe: try_from_probe(probe)?,
                },
                Vec::new(),
            ),
            packetcraftr::scan::Event::Undecoded { frame } => (
                Self::Undecoded {
                    frame: Captured::try_from_frame(frame)?,
                },
                Vec::new(),
            ),
            packetcraftr::scan::Event::Diagnostic(diagnostic) => {
                (Self::Diagnostic {}, vec![diagnostic])
            }
        };
        Ok((event, diagnostics))
    }

    pub fn complete_from_scan(
        summary: packetcraftr::scan::Summary,
    ) -> (Self, Vec<PacketDiagnostic>, Stats) {
        (
            Self::Complete {
                planned_duration: summary.planned_duration,
                target: summary.target,
                resolved_addresses: summary.resolved_addresses,
                counts: summary.counts,
                rtt: summary.rtt,
            },
            Vec::new(),
            summary.stats,
        )
    }
}

fn try_from_probe(evidence: packetcraftr::scan::ProbeEvidence) -> Result<Probe, Error> {
    let protocol = match (evidence.transport, evidence.address) {
        (Transport::Icmp, IpAddr::V4(_)) => Protocol::Icmpv4,
        (Transport::Icmp, IpAddr::V6(_)) => Protocol::Icmpv6,
        (Transport::Tcp, _) => Protocol::Tcp,
        (Transport::Udp, _) => Protocol::Udp,
    };
    Ok(Probe {
        sequence: evidence.sequence,
        protocol,
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
        application: evidence.application,
    })
}

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Sent { .. } => "probe_sent",
            Self::Probe { .. } => "probe",
            Self::Undecoded { .. } => "undecoded",
            Self::Diagnostic {} => "diagnostic",
            Self::Complete { .. } => "complete",
        }
    }
}

/// A probe still in flight when the pipeline failed, with its best response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Pending {
    pub sent: Sent,
    pub response: Option<Captured>,
}

/// The probe being prepared when the pipeline failed, before it was sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FailedProbe {
    pub sequence: u64,
    pub destination: IpAddr,
    pub destination_port: Option<u16>,
    pub transport: Transport,
    pub attempt: u32,
}

/// Per-interface capture lifecycle and statistics for a pipeline scan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureSource {
    pub interface: packetcraftr_netio::interface::Id,
    pub ready: bool,
    pub shutdown_confirmed: bool,
    pub statistics_valid: bool,
    pub statistics: packetcraftr_netio::capture::Statistics,
}

/// Pipeline failure report: partial statistics and every incomplete probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Failure {
    pub stats: Stats,
    pub pending: Vec<Pending>,
    pub failed_probe: Option<FailedProbe>,
    pub capture_sources: Vec<CaptureSource>,
}
impl Failure {
    pub fn try_from_pipeline(error: &packetcraftr::scan::PipelineError) -> Result<Self, Error> {
        Ok(Self {
            stats: error.stats.clone(),
            pending: error
                .pending
                .iter()
                .map(|entry| {
                    Ok(Pending {
                        sent: Sent::try_from_sent(entry.sent.clone())?,
                        response: entry
                            .response
                            .clone()
                            .map(Captured::try_from_frame)
                            .transpose()?,
                    })
                })
                .collect::<Result<_, Error>>()?,
            failed_probe: error.failed_probe.as_ref().map(|probe| FailedProbe {
                sequence: probe.sequence,
                destination: probe.address,
                destination_port: probe.endpoint.port(),
                transport: probe.endpoint.transport(),
                attempt: probe.attempt,
            }),
            capture_sources: error
                .capture_sources
                .iter()
                .map(|source| CaptureSource {
                    interface: source.metadata.interface.clone(),
                    ready: source.ready,
                    shutdown_confirmed: source.shutdown_confirmed,
                    statistics_valid: source.statistics_valid,
                    statistics: source.statistics,
                })
                .collect(),
        })
    }
}
