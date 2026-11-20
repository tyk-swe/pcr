// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    AdmittedProbe,
    correlation::{Best, CandidateIndex},
    expiry::PendingDeadlines,
};
use crate::{
    evidence::SentPacket,
    probe::Batch,
    scan::{PendingEvidence, Probe, SentProbe, plan::replies_overlap},
};
use packetcraftr_core::{error::BoundaryError, frame::Frame, packet::Packet, registry::Registry};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    time::Instant,
};

#[derive(Default)]
pub(super) struct PendingResponses {
    pub(super) best: Option<Best>,
    pub(super) passed: Vec<crate::exchange::Response>,
}

#[derive(Clone, Copy)]
pub(super) struct PendingView<'a> {
    pub(super) sent: &'a SentPacket,
    pub(super) deadline: Instant,
}

struct Pending {
    sent: Arc<SentPacket>,
    deadline: Instant,
    responses: PendingResponses,
    last_response: Option<Frame>,
    charge: usize,
}
pub(super) enum BatchStorage<'a> {
    Borrowed(&'a Batch<Probe>),
    Owned(Batch<Probe>),
}
impl BatchStorage<'_> {
    pub(super) fn batch(&self) -> &Batch<Probe> {
        match self {
            Self::Borrowed(batch) => batch,
            Self::Owned(batch) => batch,
        }
    }
}
pub(super) struct Descriptor<'a> {
    pub(super) batch: BatchStorage<'a>,
    pub(super) host_deadline: Option<Instant>,
    pub(super) route: Option<Box<crate::engine::preparation::AuthorizedRoute>>,
}
impl Descriptor<'_> {
    pub(super) fn probe(&self) -> &Probe {
        &self.batch.batch().probes[0]
    }
}
pub(super) struct Attempts<'a> {
    descriptions: BTreeMap<usize, Descriptor<'a>>,
    ready: BTreeMap<usize, AdmittedProbe>,
    armed_ready: BTreeSet<usize>,
    ready_deadlines: BTreeSet<(Instant, usize)>,
    pending: BTreeMap<usize, Pending>,
    raw_ip_pending: BTreeSet<usize>,
    recent: VecDeque<(usize, Arc<SentPacket>, usize)>,
    recent_sent: BTreeMap<usize, Arc<SentPacket>>,
    candidates: CandidateIndex,
    deadlines: PendingDeadlines,
    retained: usize,
    recent_capacity: usize,
    index_capacity: usize,
}

impl<'a> Attempts<'a> {
    pub(super) fn new(
        descriptions: BTreeMap<usize, Descriptor<'a>>,
        probes: Vec<AdmittedProbe>,
        sources: usize,
        capacity: usize,
        recent_capacity: usize,
        retained: usize,
    ) -> Self {
        let ready = descriptions
            .keys()
            .copied()
            .zip(probes)
            .collect::<BTreeMap<_, _>>();
        let armed_ready = ready.keys().copied().collect();
        let ready_deadlines = descriptions
            .iter()
            .filter_map(|(index, description)| {
                description.host_deadline.map(|deadline| (deadline, *index))
            })
            .collect();
        Self {
            descriptions,
            ready,
            armed_ready,
            ready_deadlines,
            pending: BTreeMap::new(),
            raw_ip_pending: BTreeSet::new(),
            recent: VecDeque::new(),
            recent_sent: BTreeMap::new(),
            candidates: CandidateIndex::new(sources, capacity),
            deadlines: PendingDeadlines::default(),
            retained,
            recent_capacity,
            index_capacity: capacity,
        }
    }

    pub(super) fn description(&self, index: usize) -> &Descriptor<'a> {
        &self.descriptions[&index]
    }

    pub(super) fn description_if(&self, index: usize) -> Option<&Descriptor<'a>> {
        self.descriptions.get(&index)
    }

    pub(super) fn contains(&self, index: usize) -> bool {
        self.descriptions.contains_key(&index)
    }

    pub(super) fn queued_count(&self) -> usize {
        self.ready.len()
    }

    pub(super) fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub(super) fn queued_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.ready.keys().copied()
    }

    pub(super) fn armed_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.armed_ready.iter().copied()
    }

    pub(super) fn reply_overlaps(&self, index: usize) -> bool {
        let next = self.description(index).probe();
        let overlaps = |pending: &usize| replies_overlap(next, self.description(*pending).probe());
        if next.endpoint.ip_protocol().is_some() {
            self.pending.keys().any(overlaps)
        } else {
            self.raw_ip_pending.iter().any(overlaps)
        }
    }

    pub(super) fn queued_memory(&self, index: usize) -> usize {
        self.ready[&index].memory
    }

    pub(super) fn pending_view(&self, index: usize) -> Option<PendingView<'_>> {
        self.pending.get(&index).map(|entry| PendingView {
            sent: entry.sent.as_ref(),
            deadline: entry.deadline,
        })
    }

    pub(super) fn responses_mut(&mut self, index: usize) -> &mut PendingResponses {
        &mut self
            .pending
            .get_mut(&index)
            .expect("candidate is pending")
            .responses
    }

    pub(super) fn discard_duplicate(&mut self) -> Option<crate::exchange::Response> {
        self.pending
            .values_mut()
            .find_map(|entry| entry.responses.passed.pop())
    }

    pub(super) fn retained(&self) -> usize {
        self.retained
    }

    pub(super) fn queue(
        &mut self,
        index: usize,
        description: Descriptor<'a>,
        admitted: AdmittedProbe,
        armed: bool,
    ) {
        if admitted.retained.is_some() {
            self.retained += admitted.memory;
        }
        if armed {
            self.armed_ready.insert(index);
        }
        if let Some(deadline) = description.host_deadline {
            self.ready_deadlines.insert((deadline, index));
        }
        self.descriptions.insert(index, description);
        self.ready.insert(index, admitted);
    }

    pub(super) fn discard_previews(&mut self, additional: usize, maximum: usize) {
        for probe in self.ready.values_mut().rev() {
            if self.retained.saturating_add(additional) <= maximum {
                break;
            }
            if let Some(preview) = probe.retained.take() {
                drop(preview);
                self.retained -= probe.memory;
            }
        }
    }

    pub(super) fn next_expired_ready(&self, now: Instant) -> Option<usize> {
        self.ready_deadlines
            .first()
            .filter(|(deadline, _)| *deadline <= now)
            .map(|(_, index)| *index)
    }

    pub(super) fn omit(&mut self, index: usize) {
        if let Some(admitted) = self.ready.remove(&index) {
            let preview = if admitted.retained.is_some() {
                admitted.memory
            } else {
                0
            };
            drop(admitted);
            self.retained -= preview;
        }
        self.armed_ready.remove(&index);
        if let Some(description) = self.descriptions.remove(&index)
            && let Some(deadline) = description.host_deadline
        {
            self.ready_deadlines.remove(&(deadline, index));
        }
    }

    pub(super) fn prepare<T>(
        &mut self,
        index: usize,
        build: impl FnOnce(&Descriptor<'a>, AdmittedProbe) -> T,
    ) -> (T, usize) {
        let admitted = self.ready.remove(&index).expect("armed attempt is queued");
        self.armed_ready.remove(&index);
        let description = &self.descriptions[&index];
        if let Some(deadline) = description.host_deadline {
            self.ready_deadlines.remove(&(deadline, index));
        }
        let memory = admitted.memory;
        let preview = if admitted.retained.is_some() {
            memory
        } else {
            0
        };
        let prepared = build(description, admitted);
        self.retained -= preview;
        (prepared, memory)
    }

    pub(super) fn record_sent(
        &mut self,
        index: usize,
        source: usize,
        sent: Arc<SentPacket>,
        deadline: Instant,
        charge: usize,
        registry: &Registry,
    ) -> Result<(), BoundaryError> {
        self.candidates
            .insert(index, source, &sent.built().packet, registry)?;
        self.deadlines.insert(deadline, index);
        self.retained += charge;
        if self
            .description(index)
            .probe()
            .endpoint
            .ip_protocol()
            .is_some()
        {
            self.raw_ip_pending.insert(index);
        }
        self.pending.insert(
            index,
            Pending {
                sent,
                deadline,
                charge,
                responses: PendingResponses::default(),
                last_response: None,
            },
        );
        Ok(())
    }

    /// Publication failure leaves the attempt pending with its last response.
    pub(super) fn complete(
        &mut self,
        index: usize,
        publish: impl FnOnce(
            &Descriptor<'a>,
            &SentPacket,
            &mut PendingResponses,
        ) -> Result<(), BoundaryError>,
    ) -> Result<(), BoundaryError> {
        let entry = self
            .pending
            .get_mut(&index)
            .expect("completed pending probe");
        entry.last_response = entry
            .responses
            .best
            .as_ref()
            .map(|best| best.response.response.frame.clone());
        publish(
            &self.descriptions[&index],
            entry.sent.as_ref(),
            &mut entry.responses,
        )?;
        let entry = self
            .pending
            .remove(&index)
            .expect("completed pending probe");
        self.raw_ip_pending.remove(&index);
        if self.recent.len() == self.recent_capacity {
            self.retire_recent();
        }
        self.deadlines.remove(entry.deadline, index);
        self.recent_sent.insert(index, entry.sent.clone());
        self.recent.push_back((index, entry.sent, entry.charge));
        Ok(())
    }

    pub(super) fn retire_recent(&mut self) -> bool {
        let Some((index, _, charge)) = self.recent.pop_front() else {
            return false;
        };
        self.candidates.remove(index);
        self.recent_sent.remove(&index);
        drop(self.descriptions.remove(&index));
        self.retained -= charge;
        true
    }

    pub(super) fn begin_epoch(&mut self, sources: usize) {
        debug_assert!(
            self.pending.is_empty(),
            "active intervals stay in their capture epoch"
        );
        while self.retire_recent() {}
        self.armed_ready = self.ready.keys().copied().collect();
        self.candidates = CandidateIndex::new(sources, self.index_capacity);
    }

    pub(super) fn candidates(&self, source: usize, packet: &Packet) -> Vec<usize> {
        self.candidates.lookup(source, packet)
    }

    pub(super) fn settled(&self, index: usize, received: Instant) -> Option<&SentPacket> {
        self.pending
            .get(&index)
            .filter(|entry| received > entry.deadline)
            .map(|entry| entry.sent.as_ref())
            .or_else(|| self.recent_sent.get(&index).map(Arc::as_ref))
    }

    pub(super) fn notice_expired(&mut self, now: Instant) -> bool {
        self.deadlines.notice_expired(now)
    }

    pub(super) fn is_draining(&self) -> bool {
        self.deadlines.is_draining()
    }

    pub(super) fn pop_expired(&mut self) -> Option<usize> {
        self.deadlines.pop_expired()
    }

    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.next()
    }

    pub(super) fn next_ready_deadline(&self) -> Option<Instant> {
        self.ready_deadlines.first().map(|(deadline, _)| *deadline)
    }

    pub(super) fn pending_evidence(&self) -> Vec<PendingEvidence> {
        self.pending
            .iter()
            .map(|(index, entry)| PendingEvidence {
                sent: SentProbe {
                    probe: self.descriptions[index].probe().clone(),
                    sent: entry.sent.clone(),
                },
                response: entry
                    .responses
                    .best
                    .as_ref()
                    .map(|best| best.response.response.frame.clone())
                    .or_else(|| entry.last_response.clone()),
            })
            .collect()
    }
}
