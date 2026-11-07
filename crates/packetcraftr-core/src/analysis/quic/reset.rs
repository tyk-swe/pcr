use super::{Collector, Datagram, State};
use crate::analysis::{ScopedFlowKey, scope};
use bytes::Bytes;
use std::time::SystemTime;

pub(super) struct Candidate {
    number: u64,
    timestamp: SystemTime,
    flow: ScopedFlowKey,
    scope: scope::Definition,
    bytes: Bytes,
    token: [u8; 16],
    sources: Vec<u64>,
    truncated: bool,
    counted: bool,
}
impl Candidate {
    fn memory(&self) -> usize {
        512 + self.bytes.len() + self.sources.len() * 8
    }
    fn input(&self) -> Datagram<'_> {
        Datagram {
            number: self.number,
            timestamp: self.timestamp,
            flow: &self.flow,
            scope: &self.scope,
            payload: &self.bytes,
            source_frames: &self.sources,
            truncated: self.truncated,
        }
    }
    fn matches(&self, state: &State) -> bool {
        self.scope.id == state.report.scope.id
            && state
                .cids
                .iter()
                .any(|cid| !cid.retired && cid.token == Some(self.token))
    }
}
impl Collector {
    pub(super) fn queue_reset(&mut self, input: &Datagram<'_>, bytes: &[u8], counted: bool) {
        let Some((prefix, token)) = bytes.split_last_chunk::<16>() else {
            return;
        };
        if prefix.len() < 5 || prefix[0] & 0xc0 != 0x40 {
            return;
        }
        let size = 512usize
            .saturating_add(bytes.len())
            .saturating_add(input.source_frames.len().saturating_mul(8));
        let retained = self.memory.saturating_add(self.keylog.memory());
        if size > self.limits.max_buffered_bytes.saturating_sub(retained) {
            self.summary.buffer_limit_hits += 1;
            return;
        }
        while self.reset_candidates.len() >= self.limits.max_pending_packets
            || retained
                .saturating_add(self.reset_memory)
                .saturating_add(size)
                > self.limits.max_buffered_bytes
        {
            if !self.drop_reset() {
                break;
            }
        }
        self.reset_candidates.push_back(Candidate {
            number: input.number,
            timestamp: input.timestamp,
            flow: input.flow.clone(),
            scope: input.scope.clone(),
            bytes: Bytes::copy_from_slice(bytes),
            token: *token,
            sources: input.source_frames.to_vec(),
            truncated: input.truncated,
            counted,
        });
        self.reset_memory = self.reset_memory.saturating_add(size);
    }
    pub(super) fn drop_reset(&mut self) -> bool {
        let Some(candidate) = self.reset_candidates.pop_front() else {
            return false;
        };
        self.reset_memory = self.reset_memory.saturating_sub(candidate.memory());
        self.summary.buffer_limit_hits += 1;
        true
    }
    pub(super) fn expire_resets(&mut self, now: SystemTime) {
        let candidates = std::mem::take(&mut self.reset_candidates);
        for candidate in candidates {
            if now
                .duration_since(candidate.timestamp)
                .is_ok_and(|age| age >= self.limits.idle_expiry)
            {
                self.reset_memory = self.reset_memory.saturating_sub(candidate.memory());
            } else {
                self.reset_candidates.push_back(candidate);
            }
        }
    }
    pub(super) fn replay_resets(&mut self, state: &mut State) {
        let candidates = std::mem::take(&mut self.reset_candidates);
        for candidate in candidates {
            if !candidate.matches(state)
                || self
                    .resets
                    .get(&(candidate.scope.id.get(), candidate.token))
                    .is_some_and(|entries| !entries.is_empty())
            {
                self.reset_candidates.push_back(candidate);
                continue;
            }
            self.reset_memory = self.reset_memory.saturating_sub(candidate.memory());
            state.record_datagram(&candidate.input(), &self.limits);
            state.report.metrics.packets += 1;
            state.report.stateless_reset = true;
            state.report.closed = true;
            self.summary.packets += 1;
            self.summary.unassociated_packets = self
                .summary
                .unassociated_packets
                .saturating_sub(u64::from(candidate.counted));
        }
    }
}
