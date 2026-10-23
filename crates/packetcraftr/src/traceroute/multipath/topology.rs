// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Change, Edge, Node, NodeKey, ProbeEvidence, Rtt, Summary, TopologyUpdate};
use std::{collections::BTreeMap, time::Duration};

#[derive(Default)]
pub(super) struct Topology {
    nodes: BTreeMap<NodeKey, Vec<Duration>>,
    edges: BTreeMap<(NodeKey, NodeKey), Vec<[u64; 2]>>,
    changes: Vec<Change>,
    previous_hop: BTreeMap<u16, (u32, NodeKey, u64)>,
    previous_sweep: BTreeMap<(u16, u8), (u32, NodeKey, u64)>,
}

fn node(key: NodeKey, samples: &[Duration]) -> Node {
    Node {
        key,
        rtt: Rtt {
            samples: samples.len(),
            minimum: samples[0],
            median: samples[(samples.len() - 1) / 2],
            maximum: samples[samples.len() - 1],
        },
    }
}

impl Topology {
    pub(super) fn observe(&mut self, probe: &ProbeEvidence) -> TopologyUpdate {
        let mut update = TopologyUpdate::default();
        for reply in &probe.replies {
            let key = NodeKey {
                hop_limit: probe.hop_limit,
                responder: reply.responder,
            };
            let samples = self.nodes.entry(key).or_default();
            samples.insert(
                samples.partition_point(|sample| *sample <= reply.latency),
                reply.latency,
            );
            update.nodes.retain(|node| node.key != key);
            update.nodes.push(node(key, samples));
        }
        let comparable = !probe.ambiguous && !probe.incomplete && !probe.replies.is_empty();
        let prior = self.previous_hop.remove(&probe.flow_id);
        let prior_sweep = self
            .previous_sweep
            .remove(&(probe.flow_id, probe.hop_limit));
        if comparable {
            let key = NodeKey {
                hop_limit: probe.hop_limit,
                responder: probe.replies[0].responder,
            };
            if let Some((sweep, from, sequence)) = prior
                && sweep == probe.sweep
                && from.hop_limit.checked_add(1) == Some(probe.hop_limit)
            {
                let evidence = self.edges.entry((from, key)).or_default();
                evidence.push([sequence, probe.sequence]);
                // Only the newly observed pair is streamed, bounding each event.
                update.edges.push(Edge {
                    from,
                    to: key,
                    evidence: vec![[sequence, probe.sequence]],
                });
            }
            if let Some((sweep, before, sequence)) = prior_sweep
                && sweep + 1 == probe.sweep
                && before.responder != key.responder
            {
                let change = Change {
                    flow_id: probe.flow_id,
                    hop_limit: probe.hop_limit,
                    previous_sweep: sweep,
                    sweep: probe.sweep,
                    before: before.responder,
                    after: key.responder,
                    evidence: [sequence, probe.sequence],
                };
                self.changes.push(change.clone());
                update.changes.push(change);
            }
            let observation = (probe.sweep, key, probe.sequence);
            self.previous_hop.insert(probe.flow_id, observation);
            self.previous_sweep
                .insert((probe.flow_id, probe.hop_limit), observation);
        }
        update
    }

    pub(super) fn finish(self, summary: &mut Summary) -> TopologyUpdate {
        let mut outgoing = BTreeMap::<NodeKey, usize>::new();
        let mut incoming = BTreeMap::<NodeKey, usize>::new();
        for (from, to) in self.edges.keys() {
            *outgoing.entry(*from).or_default() += 1;
            *incoming.entry(*to).or_default() += 1;
        }
        summary.nodes = self.nodes.len();
        summary.edges = self.edges.len();
        summary.changes = self.changes.len();
        summary.branch_points = outgoing.values().filter(|count| **count > 1).count();
        summary.rejoin_points = incoming.values().filter(|count| **count > 1).count();
        TopologyUpdate {
            nodes: self
                .nodes
                .into_iter()
                .map(|(key, samples)| node(key, &samples))
                .collect(),
            edges: self
                .edges
                .into_iter()
                .map(|((from, to), evidence)| Edge { from, to, evidence })
                .collect(),
            changes: self.changes,
        }
    }
}
