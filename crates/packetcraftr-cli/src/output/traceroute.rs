// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use super::contract::Error;
use super::envelope::Published;
use super::frame::{Captured, Timestamp};
use super::probe::{ProbeStatus, Transport};

use packetcraftr::traceroute as library;

published_enum! {
    /// What kind of node answered a traceroute probe.
    pub enum ResponseKind from library::ResponseKind {
        Intermediate => "intermediate",
        DestinationReached => "destination_reached",
        Unreachable => "unreachable",
    }
}

published_enum! {
    /// Why a traceroute stopped.
    pub enum Completion from library::Termination {
        DestinationReached => "destination_reached",
        Unreachable => "unreachable",
        MaximumHops => "maximum_hops",
        Timeout => "timeout",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub sequence: u64,
    pub hop_limit: u8,
    pub attempt: u32,
    pub strategy: Transport,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: Transport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub hops: Vec<Hop>,
    pub undecoded: Vec<Undecoded>,
    pub completion: Completion,
}

/// A traceroute, with its diagnostics and totals.
impl TryFrom<library::Aggregate> for Published<Report> {
    type Error = Error;

    fn try_from(result: library::Aggregate) -> Result<Self, Error> {
        let library::Aggregate {
            target,
            resolved_addresses,
            destination,
            strategy,
            destination_port,
            hops,
            undecoded,
            termination,
            diagnostics,
            stats,
        } = result;
        let hop_outputs = hops
            .into_iter()
            .map(|hop| {
                Ok(Hop {
                    hop_limit: hop.hop_limit,
                    probes: hop
                        .probes
                        .into_iter()
                        .map(Probe::try_from)
                        .collect::<Result<Vec<_>, Error>>()?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let undecoded_outputs = undecoded
            .into_iter()
            .map(|evidence| {
                Ok(Undecoded {
                    hop_limit: evidence.hop_limit,
                    frame: evidence.frame.try_into()?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Self::new(
            Report {
                target,
                resolved_addresses,
                destination,
                strategy: strategy.into(),
                destination_port,
                hops: hop_outputs,
                undecoded: undecoded_outputs,
                completion: termination.into(),
            },
            diagnostics,
        )
        .with_stats(stats))
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
        strategy: Transport,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_port: Option<u16>,
        completion: Completion,
    },
}

/// One traceroute event, with any diagnostic it carried for the envelope.
impl TryFrom<library::Event> for Published<Event> {
    type Error = Error;

    fn try_from(event: library::Event) -> Result<Self, Error> {
        Ok(match event {
            library::Event::Probe { target, probe } => Self::new(
                Event::Probe {
                    target: target.to_string(),
                    probe: probe.try_into()?,
                },
                Vec::new(),
            ),
            library::Event::Undecoded(evidence) => Self::new(
                Event::Undecoded {
                    hop_limit: evidence.hop_limit,
                    frame: evidence.frame.try_into()?,
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
impl From<library::Report> for Published<Event> {
    fn from(summary: library::Report) -> Self {
        Self::new(
            Event::Complete {
                target: summary.target,
                resolved_addresses: summary.resolved_addresses,
                destination: summary.destination,
                strategy: summary.strategy.into(),
                destination_port: summary.destination_port,
                completion: summary.termination.into(),
            },
            Vec::new(),
        )
        .with_stats(summary.stats)
    }
}

impl TryFrom<library::ProbeEvidence> for Probe {
    type Error = Error;

    fn try_from(probe: library::ProbeEvidence) -> Result<Self, Error> {
        Ok(Self {
            sequence: probe.sequence,
            hop_limit: probe.hop_limit,
            attempt: probe.attempt,
            strategy: probe.strategy.into(),
            destination: probe.destination,
            destination_port: probe.destination_port,
            status: probe.status.into(),
            response_kind: probe.response_kind.map(Into::into),
            responder: probe.responder,
            sent_at: probe.sent_at.try_into()?,
            received_at: probe.received_at.map(Timestamp::try_from).transpose()?,
            latency: probe.latency,
            frame: probe.response.map(Captured::try_from).transpose()?,
            reason: probe.reason,
        })
    }
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
