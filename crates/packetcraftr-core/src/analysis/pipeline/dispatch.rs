// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::time::SystemTime;

use bytes::Bytes;

use crate::protocol::identity::TcpHeader;
use crate::protocol::transport::Tcp;

use crate::analysis::conversation_index::CanonicalFlow;
use crate::analysis::pipeline::Limits;
use crate::analysis::pipeline::TcpEventRecord;
use crate::analysis::pipeline::clock::CaptureClock;
use crate::analysis::pipeline::limits::DIRECTIONS_PER_CONVERSATION;
use crate::analysis::reassembly::tcp::{
    Error as ReassemblyTcpError, Event as TcpEvent, EvictionReason, Reassembler as TcpReassembler,
    Resource as TcpResource, Segment,
};
use crate::analysis::serial::serial_range_contains;
use crate::analysis::{Error, ScopedFlowKey};

pub(super) struct ReassemblyDispatch {
    tcp_reassembler: Option<TcpReassembler>,
    conversations: HashMap<CanonicalFlow, ConversationMeta>,
    max_half_open_pure_syns: usize,
    clock: CaptureClock,
}

struct ConversationMeta {
    stream: Option<u64>,
    generation: u64,
    directions: HashMap<ScopedFlowKey, DirectionMeta>,
}

#[derive(Default)]
struct DirectionMeta {
    generation: u64,
    active: bool,
    half_open_pure_syn: bool,
    last_syn_base: Option<u32>,
    saw_prior_traffic: bool,
    closed: bool,
    closed_next_sequence: Option<u32>,
}

impl ConversationMeta {
    fn new(stream: Option<u64>) -> Self {
        Self {
            stream,
            generation: 0,
            directions: HashMap::new(),
        }
    }

    fn direction(&mut self, flow: &ScopedFlowKey) -> &mut DirectionMeta {
        self.directions.entry(flow.clone()).or_default()
    }

    fn bump_generation(&mut self) {
        self.generation = self.generation.saturating_add(1);
        for direction in self.directions.values_mut() {
            direction.generation = direction.generation.saturating_add(1);
            direction.active = false;
            direction.half_open_pure_syn = false;
            direction.saw_prior_traffic = false;
            direction.closed = false;
            direction.closed_next_sequence = None;
        }
    }
}

impl ReassemblyDispatch {
    pub(super) fn new(enabled: bool, limits: &Limits) -> Result<Self, Error> {
        let tcp_reassembler = enabled
            .then(|| TcpReassembler::new(limits.tcp.clone()))
            .transpose()?;
        Ok(Self {
            tcp_reassembler,
            conversations: HashMap::new(),
            max_half_open_pure_syns: limits.max_flows.saturating_mul(DIRECTIONS_PER_CONVERSATION),
            clock: CaptureClock::new(),
        })
    }

    fn meta(&mut self, flow: &ScopedFlowKey, stream: Option<u64>) -> &mut ConversationMeta {
        let meta = self
            .conversations
            .entry(CanonicalFlow::from_flow(flow))
            .or_insert_with(|| ConversationMeta::new(stream));
        if stream.is_some() {
            meta.stream = stream;
        }
        meta
    }

    fn stamp(&self, event: TcpEvent) -> TcpEventRecord {
        let flow = event_flow(&event);
        let meta = self.conversations.get(&CanonicalFlow::from_flow(flow));
        let direction = meta.and_then(|meta| meta.directions.get(flow));
        TcpEventRecord {
            stream: meta.and_then(|meta| meta.stream).unwrap_or(0),
            generation: meta.map_or(0, |meta| meta.generation),
            direction_generation: direction.map_or(0, |direction| direction.generation),
            event,
        }
    }

    pub(super) fn dispatch(
        &mut self,
        tcp_header: Option<TcpHeader<'_>>,
        segment: Option<&Segment>,
        stream: Option<u64>,
        timestamp: SystemTime,
        number: u64,
    ) -> Result<Vec<TcpEventRecord>, Error> {
        let mut output = Vec::new();
        if self.tcp_reassembler.is_none() {
            return Ok(output);
        }

        // Only matched frames advance TCP expiry.
        let now = self.clock.at(timestamp, number)?;
        let sweep_due = self.clock.should_sweep(now);
        let pushable = segment.as_ref().is_some_and(|segment| {
            !segment.payload.is_empty() || segment.syn || segment.fin || segment.rst
        });

        if pushable || sweep_due {
            let expired = self
                .tcp_reassembler
                .as_mut()
                .expect("reassembler checked")
                .expire(now);
            for flow in expired.iter().map(event_flow).cloned().collect::<Vec<_>>() {
                self.meta(&flow, stream).direction(&flow).active = false;
            }
            output.extend(expired.into_iter().map(|event| self.stamp(event)));
        }

        if pushable && let Some(segment) = segment {
            self.meta(&segment.flow, stream);
            output.extend(
                self.dispatch_segment(
                    tcp_header
                        .and_then(|tcp| (tcp.flags & Tcp::ACK != 0).then_some(tcp.acknowledgment)),
                    segment,
                    now,
                    number,
                )?,
            );
        }

        Ok(output)
    }

    fn dispatch_segment(
        &mut self,
        acknowledgment: Option<u32>,
        segment: &Segment,
        now: std::time::Instant,
        number: u64,
    ) -> Result<Vec<TcpEventRecord>, Error> {
        let flow = segment.flow.clone();
        let pure_syn = segment.syn && acknowledgment.is_none() && segment.payload.is_empty();
        let mut output = Vec::new();
        let reused = self.evict_reused_generation(segment, acknowledgment, &mut output);
        if reused {
            self.meta(&flow, None).bump_generation();
        }

        let mut input = if segment.rst {
            for event in [
                self.tcp_reassembler
                    .as_mut()
                    .expect("reassembler exists")
                    .evict_flow(&segment.flow.reverse(), EvictionReason::Reset),
                self.tcp_reassembler
                    .as_mut()
                    .expect("reassembler exists")
                    .evict_flow(&segment.flow, EvictionReason::Reset),
            ]
            .into_iter()
            .flatten()
            {
                output.push(self.stamp(event));
            }
            Segment {
                payload: Bytes::new(),
                ..segment.clone()
            }
        } else {
            segment.clone()
        };

        self.filter_post_fin_retransmission(&mut input);
        if input.payload.is_empty() && !input.syn && !input.fin && !input.rst {
            return Ok(output);
        }
        let produced = self.push_with_retry(input.clone(), now, number, &mut output)?;
        self.observe_segment(&input, &produced, pure_syn);
        Ok(output)
    }

    fn push_with_retry(
        &mut self,
        segment: Segment,
        now: std::time::Instant,
        number: u64,
        output: &mut Vec<TcpEventRecord>,
    ) -> Result<Vec<TcpEvent>, Error> {
        let reassembler = self.tcp_reassembler.as_mut().expect("reassembler exists");
        match reassembler.push(segment.clone(), now) {
            Ok(produced) => {
                output.extend(produced.clone().into_iter().map(|event| self.stamp(event)));
                Ok(produced)
            }
            Err(ReassemblyTcpError::Resource(
                TcpResource::FlowByteLimit { .. }
                | TcpResource::SegmentLimit { .. }
                | TcpResource::AggregateByteLimit { .. },
            )) => {
                for event in reassembler.evict_flow(&segment.flow, EvictionReason::Budget) {
                    output.push(self.stamp(event));
                }
                let produced = reassembler
                    .push(segment, now)
                    .map_err(|source| Error::Reassembly { number, source })?;
                output.extend(produced.clone().into_iter().map(|event| self.stamp(event)));
                Ok(produced)
            }
            Err(source) => Err(Error::Reassembly { number, source }),
        }
    }

    fn evict_reused_generation(
        &mut self,
        segment: &Segment,
        acknowledgment: Option<u32>,
        output: &mut Vec<TcpEventRecord>,
    ) -> bool {
        if !segment.syn {
            return false;
        }
        let first = segment.sequence.wrapping_add(1);
        let reverse = segment.flow.reverse();
        let reassembler = self.tcp_reassembler.as_mut().expect("reassembler exists");
        let reverse_verdict = acknowledgment.and_then(|acknowledgment| {
            serial_range_contains(
                reassembler.flow_base_sequence(&reverse),
                reassembler.flow_next_sequence(&reverse),
                acknowledgment,
            )
        });
        let acknowledgment_disagrees = reverse_verdict == Some(false);
        let own_base = reassembler.flow_base_sequence(&segment.flow);
        let reverse_half_open = self
            .conversations
            .get(&CanonicalFlow::from_flow(&segment.flow))
            .and_then(|meta| meta.directions.get(&reverse))
            .is_some_and(|direction| direction.half_open_pure_syn);
        let reuse = match own_base {
            Some(base) => {
                base != first
                    || acknowledgment_disagrees
                    || (acknowledgment.is_none()
                        && segment.payload.is_empty()
                        && reassembler.flow_observed_payload(&segment.flow))
            }
            None if acknowledgment.is_some() => acknowledgment_disagrees,
            None => !reverse_half_open,
        };
        if !reuse {
            return false;
        }
        if reverse_verdict != Some(true) {
            for event in reassembler.evict_flow(&reverse, EvictionReason::Reuse) {
                output.push(self.stamp(event));
            }
        }
        if own_base.is_some() {
            for event in reassembler.evict_flow(&segment.flow, EvictionReason::Reuse) {
                output.push(self.stamp(event));
            }
        }
        true
    }

    fn filter_post_fin_retransmission(&mut self, segment: &mut Segment) {
        if segment.syn {
            return;
        }
        let Some(direction) = self
            .conversations
            .get(&CanonicalFlow::from_flow(&segment.flow))
            .and_then(|meta| meta.directions.get(&segment.flow))
        else {
            return;
        };
        if !direction.closed {
            return;
        }
        let Some(edge) = direction.closed_next_sequence else {
            return;
        };
        let sequence = segment.sequence;
        let overlap = edge.wrapping_sub(sequence);
        if overlap == 0 {
            return;
        }
        let payload_overlap = usize::try_from(overlap)
            .unwrap_or(usize::MAX)
            .min(segment.payload.len());
        if payload_overlap != 0 {
            segment.sequence = segment.sequence.wrapping_add(payload_overlap as u32);
            segment.payload = segment.payload.slice(payload_overlap..);
        }
        if segment.fin
            && segment.payload.len() + usize::try_from(overlap).unwrap_or(usize::MAX) != 0
            && segment.payload.is_empty()
        {
            segment.fin = false;
        }
    }

    fn observe_segment(&mut self, segment: &Segment, produced: &[TcpEvent], pure_syn: bool) {
        let meta = self.meta(&segment.flow, None);
        let direction = meta.direction(&segment.flow);
        direction.active = true;
        direction.half_open_pure_syn = pure_syn;
        if segment.syn {
            direction.last_syn_base = Some(segment.sequence.wrapping_add(1));
        }
        direction.saw_prior_traffic |= !segment.payload.is_empty()
            || produced
                .iter()
                .any(|event| matches!(event, TcpEvent::Data { .. }));
        for event in produced {
            if let TcpEvent::Closed { flow, reset } = event
                && flow == &segment.flow
            {
                let direction = meta.direction(flow);
                direction.closed = true;
                direction.active = false;
                if !reset {
                    direction.closed_next_sequence = Some(
                        segment
                            .sequence
                            .wrapping_add(u32::from(segment.syn))
                            .wrapping_add(segment.payload.len() as u32)
                            .wrapping_add(1),
                    );
                }
            }
        }
    }

    pub(super) fn flush(&mut self) -> Vec<TcpEventRecord> {
        self.tcp_reassembler
            .as_mut()
            .map(TcpReassembler::flush)
            .unwrap_or_default()
            .into_iter()
            .map(|event| self.stamp(event))
            .collect()
    }
}

fn event_flow(event: &TcpEvent) -> &ScopedFlowKey {
    match event {
        TcpEvent::Data { flow, .. }
        | TcpEvent::Retransmission { flow, .. }
        | TcpEvent::Gap { flow, .. }
        | TcpEvent::Closed { flow, .. }
        | TcpEvent::Evicted { flow, .. } => flow,
    }
}
