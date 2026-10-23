// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::{
    contract::Error,
    envelope::Published,
    frame::{Captured, Timestamp},
    stream::StreamRecord,
};
use packetcraftr::traceroute::multipath as library;
use serde::Serialize;
use std::{net::IpAddr, time::Duration};

const MODE: &str = "multipath";

#[derive(Clone, Debug, Serialize)]
pub struct Reply {
    pub responder: IpAddr,
    pub kind: packetcraftr::traceroute::ResponseKind,
    pub latency: Duration,
    pub frame: Captured,
}

impl TryFrom<library::Reply> for Reply {
    type Error = Error;
    fn try_from(value: library::Reply) -> Result<Self, Error> {
        Ok(Self {
            responder: value.responder,
            kind: value.kind,
            latency: value.latency,
            frame: value.frame.try_into()?,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Probe {
    pub sequence: u64,
    pub flow_id: u16,
    pub sweep: u32,
    pub hop_limit: u8,
    pub sent_at: Timestamp,
    pub replies_seen: usize,
    pub ambiguous: bool,
    pub incomplete: bool,
    pub replies: Vec<Reply>,
}

impl TryFrom<library::ProbeEvidence> for Probe {
    type Error = Error;
    fn try_from(value: library::ProbeEvidence) -> Result<Self, Error> {
        Ok(Self {
            sequence: value.sequence,
            flow_id: value.flow_id,
            sweep: value.sweep,
            hop_limit: value.hop_limit,
            sent_at: value.sent_at.try_into()?,
            replies_seen: value.replies_seen,
            ambiguous: value.ambiguous,
            incomplete: value.incomplete,
            replies: value
                .replies
                .into_iter()
                .map(Reply::try_from)
                .collect::<Result<_, Error>>()?,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Unmatched {
    pub sweep: u32,
    pub hop_limit: u8,
    pub frame: Captured,
}

impl TryFrom<library::Unmatched> for Unmatched {
    type Error = Error;
    fn try_from(value: library::Unmatched) -> Result<Self, Error> {
        Ok(Self {
            sweep: value.sweep,
            hop_limit: value.hop_limit,
            frame: value.frame.try_into()?,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub mode: &'static str,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: packetcraftr::probe::Transport,
    pub flows: Vec<library::Flow>,
    pub flow_summaries: Vec<library::FlowSummary>,
    pub completions: Vec<library::FlowCompletion>,
    pub topology: library::TopologyUpdate,
    pub summary: library::Summary,
    pub probes: Vec<Probe>,
    pub unmatched: Vec<Unmatched>,
}

impl TryFrom<library::Aggregate> for Published<Report> {
    type Error = Error;
    fn try_from(value: library::Aggregate) -> Result<Self, Error> {
        let report = value.report;
        Ok(Self::new(
            Report {
                mode: MODE,
                target: report.target,
                resolved_addresses: report.resolved_addresses,
                destination: report.destination,
                strategy: report.strategy,
                flows: report.flows,
                flow_summaries: report.flow_summaries,
                completions: report.completions,
                topology: report.topology,
                summary: report.summary,
                probes: value
                    .probes
                    .into_iter()
                    .map(Probe::try_from)
                    .collect::<Result<_, _>>()?,
                unmatched: value
                    .unmatched
                    .into_iter()
                    .map(Unmatched::try_from)
                    .collect::<Result<_, Error>>()?,
            },
            value.diagnostics,
        )
        .with_stats(report.stats))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub mode: &'static str,
    #[serde(flatten)]
    pub detail: Detail,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Detail {
    Flow {
        flow: library::Flow,
    },
    Probe {
        probe: Probe,
    },
    Topology {
        topology: library::TopologyUpdate,
    },
    FlowComplete {
        completion: library::FlowCompletion,
    },
    Unmatched {
        unmatched: Unmatched,
    },
    Complete {
        target: String,
        resolved_addresses: Vec<IpAddr>,
        destination: IpAddr,
        strategy: packetcraftr::probe::Transport,
        summary: library::Summary,
        flow_summaries: Vec<library::FlowSummary>,
    },
    Diagnostic {},
}

impl TryFrom<library::Event> for Published<Event> {
    type Error = Error;
    fn try_from(value: library::Event) -> Result<Self, Error> {
        let mut diagnostics = Vec::new();
        let detail = match value {
            library::Event::Flow(flow) => Detail::Flow { flow },
            library::Event::Probe(probe) => Detail::Probe {
                probe: probe.try_into()?,
            },
            library::Event::Topology(topology) => Detail::Topology { topology },
            library::Event::FlowComplete(completion) => Detail::FlowComplete { completion },
            library::Event::Unmatched(unmatched) => Detail::Unmatched {
                unmatched: unmatched.try_into()?,
            },
            library::Event::Diagnostic(diagnostic) => {
                diagnostics.push(diagnostic);
                Detail::Diagnostic {}
            }
        };
        Ok(Self::new(Event { mode: MODE, detail }, diagnostics))
    }
}

impl From<library::Report> for Published<Event> {
    fn from(report: library::Report) -> Self {
        Self::new(
            Event {
                mode: MODE,
                detail: Detail::Complete {
                    target: report.target,
                    resolved_addresses: report.resolved_addresses,
                    destination: report.destination,
                    strategy: report.strategy,
                    summary: report.summary,
                    flow_summaries: report.flow_summaries,
                },
            },
            Vec::new(),
        )
        .with_stats(report.stats)
    }
}

impl StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self.detail {
            Detail::Flow { .. } => "flow",
            Detail::Probe { .. } => "probe",
            Detail::Topology { .. } => "topology",
            Detail::FlowComplete { .. } => "flow_complete",
            Detail::Unmatched { .. } => "unmatched",
            Detail::Complete { .. } => "complete",
            Detail::Diagnostic {} => "diagnostic",
        }
    }
}

#[cfg(test)]
mod tests;
