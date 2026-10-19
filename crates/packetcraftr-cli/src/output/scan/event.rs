// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The streaming contract: the events a scan publishes as it runs.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr::probe::Transport;

use packetcraftr::scan as library;

use super::plan::{Inference, Plan};
use super::probe::{Probe, Qualification, Sent};
use super::{Classification, ClassificationCounts, Rtt, Scheduling, Scope, Unattributed};
use crate::output::contract::Error;
use crate::output::envelope::Published;
use crate::output::frame::Captured;
use crate::output::stream::StreamRecord;

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
    Unattributed {
        unattributed: Unattributed,
    },
    Diagnostic {},
    Qualification {
        qualification: Qualification,
    },
    /// One per endpoint after the last probe, before `complete`: the
    /// inference over attempts already published as `probe` records.
    Endpoint {
        endpoint: EndpointSummary,
    },
    Complete {
        planned_duration: Duration,
        target: String,
        resolved_addresses: Vec<IpAddr>,
        plan: Plan,
        counts: ClassificationCounts,
        retained_evidence_bytes: usize,
        rtt: Rtt,
        scheduling: Scheduling,
        #[serde(skip_serializing_if = "Option::is_none")]
        traceroute: Option<crate::output::traceroute::hosts::Complete>,
    },
}

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
            library::Event::Unattributed(unattributed) => Self::new(
                Event::Unattributed {
                    unattributed: unattributed.try_into()?,
                },
                Vec::new(),
            ),
            library::Event::Qualification(qualification) => Self::new(
                Event::Qualification {
                    qualification: qualification.into(),
                },
                Vec::new(),
            ),
            library::Event::Diagnostic(diagnostic) => {
                Self::new(Event::Diagnostic {}, vec![diagnostic])
            }
        })
    }
}

/// An endpoint without its attempts, which the stream already carried.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EndpointSummary {
    pub address: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    pub transport: Transport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_protocol: Option<u8>,
    pub classification: Classification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_hint: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference: Option<Inference>,
    pub probes: Vec<u64>,
}

impl From<library::Endpoint> for Published<Event> {
    fn from(endpoint: library::Endpoint) -> Self {
        Self::new(
            Event::Endpoint {
                endpoint: EndpointSummary {
                    address: endpoint.address,
                    scope: endpoint.scope.as_ref().map(Scope::from),
                    transport: endpoint.transport,
                    port: endpoint.port,
                    ip_protocol: endpoint.ip_protocol,
                    classification: endpoint.classification.into(),
                    port_hint: endpoint.port_hint,
                    inference: endpoint.inference.map(Inference::from),
                    probes: endpoint.probes.iter().map(|probe| probe.sequence).collect(),
                },
            },
            Vec::new(),
        )
    }
}

impl
    From<(
        library::Report,
        Plan,
        Option<crate::output::traceroute::hosts::Complete>,
    )> for Published<Event>
{
    fn from(
        (summary, plan, traceroute): (
            library::Report,
            Plan,
            Option<crate::output::traceroute::hosts::Complete>,
        ),
    ) -> Self {
        Self::new(
            Event::Complete {
                planned_duration: summary.planned_duration,
                target: summary.target,
                resolved_addresses: summary.resolved_addresses,
                plan,
                counts: summary.counts.into(),
                retained_evidence_bytes: summary.retained_evidence_bytes,
                rtt: summary.rtt.into(),
                scheduling: summary.scheduling.into(),
                traceroute,
            },
            Vec::new(),
        )
        .with_stats(summary.stats)
    }
}

impl StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Sent { .. } => "probe_sent",
            Self::Probe { .. } => "probe",
            Self::Undecoded { .. } => "undecoded",
            Self::Unattributed { .. } => "unattributed",
            Self::Diagnostic {} => "diagnostic",
            Self::Qualification { .. } => "observation_quality",
            Self::Endpoint { .. } => "endpoint",
            Self::Complete { .. } => "complete",
        }
    }
}
