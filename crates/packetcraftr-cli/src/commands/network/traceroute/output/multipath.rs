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
    pub kind: super::ResponseKind,
    pub latency: Duration,
    pub frame: Captured,
}

impl TryFrom<library::Reply> for Reply {
    type Error = Error;
    fn try_from(value: library::Reply) -> Result<Self, Error> {
        Ok(Self {
            responder: value.responder,
            kind: value.kind.into(),
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
    pub strategy: crate::output::network::Transport,
    pub flows: Vec<Flow>,
    pub flow_summaries: Vec<FlowSummary>,
    pub completions: Vec<FlowCompletion>,
    pub topology: TopologyUpdate,
    pub summary: Summary,
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
                strategy: report.strategy.into(),
                flows: report.flows.into_iter().map(Into::into).collect(),
                flow_summaries: report.flow_summaries.into_iter().map(Into::into).collect(),
                completions: report.completions.into_iter().map(Into::into).collect(),
                topology: report.topology.into(),
                summary: report.summary.into(),
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
        flow: Flow,
    },
    Probe {
        probe: Probe,
    },
    Topology {
        topology: TopologyUpdate,
    },
    FlowComplete {
        completion: FlowCompletion,
    },
    Unmatched {
        unmatched: Unmatched,
    },
    Complete {
        target: String,
        resolved_addresses: Vec<IpAddr>,
        destination: IpAddr,
        strategy: crate::output::network::Transport,
        summary: Summary,
        flow_summaries: Vec<FlowSummary>,
    },
    Diagnostic {},
}

impl TryFrom<library::Event> for Published<Event> {
    type Error = Error;
    fn try_from(value: library::Event) -> Result<Self, Error> {
        let mut diagnostics = Vec::new();
        let detail = match value {
            library::Event::Flow(flow) => Detail::Flow { flow: flow.into() },
            library::Event::Probe(probe) => Detail::Probe {
                probe: probe.try_into()?,
            },
            library::Event::Topology(topology) => Detail::Topology {
                topology: topology.into(),
            },
            library::Event::FlowComplete(completion) => Detail::FlowComplete {
                completion: completion.into(),
            },
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
                    strategy: report.strategy.into(),
                    summary: report.summary.into(),
                    flow_summaries: report.flow_summaries.into_iter().map(Into::into).collect(),
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Flow {
    pub id: u16,
    pub destination: IpAddr,
    pub strategy: crate::output::network::Transport,
    pub source: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub icmp_identifier: Option<u16>,
    pub ipv6_flow_label: Option<u32>,
}

impl From<library::Flow> for Flow {
    fn from(value: library::Flow) -> Self {
        Self {
            id: value.id,
            destination: value.destination,
            strategy: value.strategy.into(),
            source: value.source,
            source_port: value.source_port,
            destination_port: value.destination_port,
            icmp_identifier: value.icmp_identifier,
            ipv6_flow_label: value.ipv6_flow_label,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeKey {
    pub hop_limit: u8,
    pub responder: IpAddr,
}

impl From<library::NodeKey> for NodeKey {
    fn from(value: library::NodeKey) -> Self {
        Self {
            hop_limit: value.hop_limit,
            responder: value.responder,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Rtt {
    pub samples: usize,
    pub minimum: Duration,
    pub median: Duration,
    pub maximum: Duration,
}

impl From<library::Rtt> for Rtt {
    fn from(value: library::Rtt) -> Self {
        Self {
            samples: value.samples,
            minimum: value.minimum,
            median: value.median,
            maximum: value.maximum,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Node {
    #[serde(flatten)]
    pub key: NodeKey,
    pub rtt: Rtt,
}

impl From<library::Node> for Node {
    fn from(value: library::Node) -> Self {
        Self {
            key: value.key.into(),
            rtt: value.rtt.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Edge {
    pub from: NodeKey,
    pub to: NodeKey,
    pub evidence: Vec<[u64; 2]>,
}

impl From<library::Edge> for Edge {
    fn from(value: library::Edge) -> Self {
        Self {
            from: value.from.into(),
            to: value.to.into(),
            evidence: value.evidence,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Change {
    pub flow_id: u16,
    pub hop_limit: u8,
    pub previous_sweep: u32,
    pub sweep: u32,
    pub before: IpAddr,
    pub after: IpAddr,
    pub evidence: [u64; 2],
}

impl From<library::Change> for Change {
    fn from(value: library::Change) -> Self {
        Self {
            flow_id: value.flow_id,
            hop_limit: value.hop_limit,
            previous_sweep: value.previous_sweep,
            sweep: value.sweep,
            before: value.before,
            after: value.after,
            evidence: value.evidence,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TopologyUpdate {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub changes: Vec<Change>,
}

impl From<library::TopologyUpdate> for TopologyUpdate {
    fn from(value: library::TopologyUpdate) -> Self {
        Self {
            nodes: value.nodes.into_iter().map(Into::into).collect(),
            edges: value.edges.into_iter().map(Into::into).collect(),
            changes: value.changes.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlowCompletion {
    pub flow_id: u16,
    pub sweep: u32,
    pub completion: super::Completion,
    pub last_hop: u8,
}

impl From<library::FlowCompletion> for FlowCompletion {
    fn from(value: library::FlowCompletion) -> Self {
        Self {
            flow_id: value.flow_id,
            sweep: value.sweep,
            completion: value.completion.into(),
            last_hop: value.last_hop,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlowSummary {
    pub flow_id: u16,
    pub probes_sent: usize,
    pub answered_probes: usize,
    pub unanswered_probes: usize,
    pub ambiguous_probes: usize,
    pub sweeps_reached: u32,
    pub destination_rtt: Option<Rtt>,
}

impl From<library::FlowSummary> for FlowSummary {
    fn from(value: library::FlowSummary) -> Self {
        Self {
            flow_id: value.flow_id,
            probes_sent: value.probes_sent,
            answered_probes: value.answered_probes,
            unanswered_probes: value.unanswered_probes,
            ambiguous_probes: value.ambiguous_probes,
            sweeps_reached: value.sweeps_reached,
            destination_rtt: value.destination_rtt.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub planned_probes: usize,
    pub probes_sent: usize,
    pub answered_probes: usize,
    pub unanswered_probes: usize,
    pub replies_seen: usize,
    pub ambiguous_probes: usize,
    pub cleanup_packets: u64,
    pub retained_evidence_bytes: usize,
    pub omitted_frames: usize,
    pub incomplete: bool,
    pub sweeps_completed: u32,
    pub nodes: usize,
    pub edges: usize,
    pub branch_points: usize,
    pub rejoin_points: usize,
    pub changes: usize,
}

impl From<library::Summary> for Summary {
    fn from(value: library::Summary) -> Self {
        Self {
            planned_probes: value.planned_probes,
            probes_sent: value.probes_sent,
            answered_probes: value.answered_probes,
            unanswered_probes: value.unanswered_probes,
            replies_seen: value.replies_seen,
            ambiguous_probes: value.ambiguous_probes,
            cleanup_packets: value.cleanup_packets,
            retained_evidence_bytes: value.retained_evidence_bytes,
            omitted_frames: value.omitted_frames,
            incomplete: value.incomplete,
            sweeps_completed: value.sweeps_completed,
            nodes: value.nodes,
            edges: value.edges,
            branch_points: value.branch_points,
            rejoin_points: value.rejoin_points,
            changes: value.changes,
        }
    }
}
