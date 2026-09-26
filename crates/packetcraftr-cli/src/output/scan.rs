// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan reports: packet probes, plus socket-only TCP connect scans in
//! [`connect`].

pub mod connect;

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use super::capture::Statistics as CaptureStatistics;
use super::contract::Error;
use super::envelope::{Published, Stats};
use super::frame::{Captured, Timestamp};
use super::network::InterfaceId;
use super::probe::{ProbeStatus, Transport};

use packetcraftr::probe::Transport as ProbeTransport;
use packetcraftr::scan as library;

published_enum! {
    /// What a probe's response, or its absence, says about an endpoint.
    pub enum Classification from library::Classification {
        Open => "open",
        Closed => "closed",
        Filtered => "filtered",
        Unreachable => "unreachable",
        Unknown => "unknown",
        Timeout => "timeout",
    }
}

/// Endpoints per final classification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ClassificationCounts {
    pub open: usize,
    pub closed: usize,
    pub filtered: usize,
    pub unreachable: usize,
    pub unknown: usize,
    pub timeout: usize,
}

impl From<library::ClassificationCounts> for ClassificationCounts {
    fn from(value: library::ClassificationCounts) -> Self {
        Self {
            open: value.open,
            closed: value.closed,
            filtered: value.filtered,
            unreachable: value.unreachable,
            unknown: value.unknown,
            timeout: value.timeout,
        }
    }
}

/// Round-trip accounting across a run's probes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Rtt {
    pub sent: u64,
    pub received: u64,
    pub lost: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<Duration>,
}

impl From<library::Rtt> for Rtt {
    fn from(value: library::Rtt) -> Self {
        Self {
            sent: value.sent,
            received: value.received,
            lost: value.lost,
            min: value.min,
            avg: value.avg,
            max: value.max,
        }
    }
}

published_enum! {
    /// How far a UDP profile's expected response was verified.
    pub enum ApplicationStatus from library::profile::Status {
        NotObserved => "not_observed",
        Unchecked => "unchecked",
        Confirmed => "confirmed",
        Rejected => "rejected",
    }
}

/// What a UDP profile established about the application behind a port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApplicationEvidence {
    pub profile: String,
    pub status: ApplicationStatus,
    pub reason: String,
}

impl From<library::profile::Evidence> for ApplicationEvidence {
    fn from(value: library::profile::Evidence) -> Self {
        Self {
            profile: value.profile,
            status: value.status.into(),
            reason: value.reason,
        }
    }
}

/// The wire protocol one probe was sent over. [`Transport::Icmp`] splits by
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

impl From<(ProbeTransport, IpAddr)> for Protocol {
    fn from((transport, address): (ProbeTransport, IpAddr)) -> Self {
        match (transport, address) {
            (ProbeTransport::Tcp, _) => Self::Tcp,
            (ProbeTransport::Udp, _) => Self::Udp,
            (ProbeTransport::Icmp, IpAddr::V4(_)) => Self::Icmpv4,
            (ProbeTransport::Icmp, IpAddr::V6(_)) => Self::Icmpv6,
        }
    }
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
    pub application: Option<ApplicationEvidence>,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub planned_duration: Duration,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub endpoints: Vec<Endpoint>,
    pub undecoded: Vec<Captured>,
    pub rtt: Rtt,
}

/// A scan, with its diagnostics and totals.
impl TryFrom<library::Report> for Published<Report> {
    type Error = Error;

    fn try_from(result: library::Report) -> Result<Self, Error> {
        let library::Report {
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
            .map(Endpoint::try_from)
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Self::new(
            Report {
                planned_duration,
                target,
                resolved_addresses,
                endpoints: endpoint_outputs,
                undecoded: undecoded
                    .into_iter()
                    .map(Captured::try_from)
                    .collect::<Result<_, _>>()?,
                rtt: rtt.into(),
            },
            diagnostics,
        )
        .with_stats(stats))
    }
}

impl TryFrom<library::Endpoint> for Endpoint {
    type Error = Error;

    fn try_from(endpoint: library::Endpoint) -> Result<Self, Error> {
        Ok(Self {
            address: endpoint.address,
            transport: endpoint.transport.into(),
            port: endpoint.port,
            classification: endpoint.classification.into(),
            probes: endpoint
                .probes
                .into_iter()
                .map(Probe::try_from)
                .collect::<Result<_, Error>>()?,
        })
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
impl TryFrom<library::SentProbe> for Sent {
    type Error = Error;

    fn try_from(value: library::SentProbe) -> Result<Self, Error> {
        let probe = value.probe;
        let sent = value.sent;
        Ok(Self {
            sequence: probe.sequence,
            udp_profile: probe
                .udp_profile
                .as_ref()
                .map(|profile| profile.name().to_owned()),
            protocol: (probe.endpoint.transport(), probe.address).into(),
            destination: probe.address,
            destination_port: probe.endpoint.port(),
            attempt: probe.attempt,
            sent_at: Timestamp::try_from(sent.timing().freshness_marker().wall_clock())?,
            frame: sent.wire_bytes().clone().into(),
            route: sent.route().clone().try_into()?,
        })
    }
}

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
        rtt: Rtt,
    },
}

/// One scan event, with any diagnostic it carried for the envelope.
impl TryFrom<library::Event> for Published<Event> {
    type Error = Error;

    fn try_from(event: library::Event) -> Result<Self, Error> {
        Ok(match event {
            library::Event::Sent(sent) => Self::new(
                Event::Sent {
                    sent: sent.try_into()?,
                },
                Vec::new(),
            ),
            library::Event::Probe { target, probe } => Self::new(
                Event::Probe {
                    target: target.to_string(),
                    probe: probe.try_into()?,
                },
                Vec::new(),
            ),
            library::Event::Undecoded { frame } => Self::new(
                Event::Undecoded {
                    frame: frame.try_into()?,
                },
                Vec::new(),
            ),
            library::Event::Diagnostic(diagnostic) => {
                Self::new(Event::Diagnostic {}, vec![diagnostic])
            }
        })
    }
}

/// The terminal record, with the run's totals.
impl From<library::Summary> for Published<Event> {
    fn from(summary: library::Summary) -> Self {
        Self::new(
            Event::Complete {
                planned_duration: summary.planned_duration,
                target: summary.target,
                resolved_addresses: summary.resolved_addresses,
                counts: summary.counts.into(),
                rtt: summary.rtt.into(),
            },
            Vec::new(),
        )
        .with_stats(summary.stats)
    }
}

impl TryFrom<library::ProbeEvidence> for Probe {
    type Error = Error;

    fn try_from(evidence: library::ProbeEvidence) -> Result<Self, Error> {
        Ok(Self {
            sequence: evidence.sequence,
            protocol: (evidence.transport, evidence.address).into(),
            destination: evidence.address,
            destination_port: evidence.port,
            attempt: evidence.attempt,
            status: evidence.status.into(),
            classification: evidence.classification.into(),
            responder: evidence.responder,
            sent_at: evidence.sent_at.try_into()?,
            received_at: evidence.received_at.map(Timestamp::try_from).transpose()?,
            latency: evidence.latency,
            frame: evidence.response.map(Captured::try_from).transpose()?,
            reason: evidence.reason,
            application: evidence.application.map(Into::into),
        })
    }
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
    pub interface: InterfaceId,
    pub ready: bool,
    pub shutdown_confirmed: bool,
    pub statistics_valid: bool,
    pub statistics: CaptureStatistics,
}

/// Pipeline failure report: partial statistics and every incomplete probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Failure {
    pub stats: Stats,
    pub pending: Vec<Pending>,
    pub failed_probe: Option<FailedProbe>,
    pub capture_sources: Vec<CaptureSource>,
}
impl TryFrom<&library::PipelineError> for Failure {
    type Error = Error;

    fn try_from(error: &library::PipelineError) -> Result<Self, Error> {
        Ok(Self {
            stats: (&error.stats).into(),
            pending: error
                .pending
                .iter()
                .map(|entry| {
                    Ok(Pending {
                        sent: entry.sent.clone().try_into()?,
                        response: entry.response.clone().map(Captured::try_from).transpose()?,
                    })
                })
                .collect::<Result<_, Error>>()?,
            failed_probe: error.failed_probe.as_ref().map(|probe| FailedProbe {
                sequence: probe.sequence,
                destination: probe.address,
                destination_port: probe.endpoint.port(),
                transport: probe.endpoint.transport().into(),
                attempt: probe.attempt,
            }),
            capture_sources: error
                .capture_sources
                .iter()
                .map(|source| CaptureSource {
                    interface: (&source.metadata.interface).into(),
                    ready: source.ready,
                    shutdown_confirmed: source.shutdown_confirmed,
                    statistics_valid: source.statistics_valid,
                    statistics: source.statistics.into(),
                })
                .collect(),
        })
    }
}
