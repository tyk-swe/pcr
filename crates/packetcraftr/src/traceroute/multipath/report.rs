// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::traceroute::{Error, ResponseKind, Termination};
use crate::{Sink, Stats, engine::execution::Shared};
use packetcraftr_core::{diagnostic::Diagnostic, error::BoundaryError, frame::Frame};
use serde::Serialize;
use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Flow {
    pub id: u16,
    pub destination: IpAddr,
    pub strategy: crate::probe::Transport,
    pub source: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub icmp_identifier: Option<u16>,
    pub ipv6_flow_label: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct Reply {
    pub responder: IpAddr,
    pub kind: ResponseKind,
    pub latency: Duration,
    pub frame: Frame,
}

#[derive(Clone, Debug)]
pub struct Unmatched {
    pub sweep: u32,
    pub hop_limit: u8,
    pub frame: Frame,
}

#[derive(Clone, Debug)]
pub struct ProbeEvidence {
    pub sequence: u64,
    pub flow_id: u16,
    pub sweep: u32,
    pub hop_limit: u8,
    pub sent_at: SystemTime,
    pub replies_seen: usize,
    pub ambiguous: bool,
    pub incomplete: bool,
    pub replies: Vec<Reply>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NodeKey {
    pub hop_limit: u8,
    pub responder: IpAddr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Rtt {
    pub samples: usize,
    pub minimum: Duration,
    /// The lower median for even sample counts.
    pub median: Duration,
    pub maximum: Duration,
}

impl Rtt {
    pub(super) fn from_sorted(samples: &[Duration]) -> Option<Self> {
        Some(Self {
            samples: samples.len(),
            minimum: *samples.first()?,
            median: samples[(samples.len() - 1) / 2],
            maximum: *samples.last()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Node {
    #[serde(flatten)]
    pub key: NodeKey,
    pub rtt: Rtt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Edge {
    pub from: NodeKey,
    pub to: NodeKey,
    /// Consecutive-hop probe sequences in one flow and sweep.
    pub evidence: Vec<[u64; 2]>,
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TopologyUpdate {
    /// Node snapshots replace their previous values. Edge evidence is appended.
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub changes: Vec<Change>,
}

impl TopologyUpdate {
    pub(super) fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.edges.is_empty() && self.changes.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlowCompletion {
    pub flow_id: u16,
    pub sweep: u32,
    pub completion: Termination,
    pub last_hop: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FlowSummary {
    pub flow_id: u16,
    pub probes_sent: usize,
    pub answered_probes: usize,
    pub unanswered_probes: usize,
    pub ambiguous_probes: usize,
    pub sweeps_reached: u32,
    pub destination_rtt: Option<Rtt>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
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

#[derive(Clone, Debug)]
pub enum Event {
    Flow(Flow),
    Probe(ProbeEvidence),
    Topology(TopologyUpdate),
    FlowComplete(FlowCompletion),
    Unmatched(Unmatched),
    Diagnostic(Diagnostic),
}

#[derive(Clone, Debug)]
pub struct Report {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: crate::probe::Transport,
    pub flows: Vec<Flow>,
    pub flow_summaries: Vec<FlowSummary>,
    pub completions: Vec<FlowCompletion>,
    pub topology: TopologyUpdate,
    pub summary: Summary,
    pub stats: Stats,
}

#[derive(Clone, Debug)]
pub struct Aggregate {
    pub report: Report,
    pub probes: Vec<ProbeEvidence>,
    pub unmatched: Vec<Unmatched>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Default)]
pub struct Collector(Shared<Collected>);

#[derive(Default)]
struct Collected {
    probes: Vec<ProbeEvidence>,
    unmatched: Vec<Unmatched>,
    diagnostics: Vec<Diagnostic>,
    flows: Vec<Flow>,
    completions: Vec<FlowCompletion>,
    incoherent: bool,
}

impl Sink<Event> for Collector {
    type Ack = ();
    fn delivery(&self) -> crate::Delivery {
        crate::Delivery::Cooperative
    }
    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.update(|state| match event {
            Event::Probe(probe) => {
                state.incoherent |= state
                    .probes
                    .last()
                    .is_some_and(|last| last.sequence >= probe.sequence);
                state.probes.push(probe);
            }
            Event::Unmatched(unmatched) => state.unmatched.push(unmatched),
            Event::Diagnostic(diagnostic) => state.diagnostics.push(diagnostic),
            Event::Flow(flow) => state.flows.push(flow),
            Event::FlowComplete(completion) => state.completions.push(completion),
            Event::Topology(_) => {}
        });
        Ok(())
    }
}

impl Collector {
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let state = self.0.take();
        if state.incoherent
            || state.probes.len() != report.summary.probes_sent
            || state.flows != report.flows
            || state.completions != report.completions
            || report.summary.probes_sent as u64 + report.summary.cleanup_packets
                != report.stats.packets_attempted
        {
            return Err(Error::IncoherentEvents {
                message: "multipath events do not match the completed operation".into(),
            });
        }
        Ok(Aggregate {
            report,
            probes: state.probes,
            unmatched: state.unmatched,
            diagnostics: state.diagnostics,
        })
    }
}
