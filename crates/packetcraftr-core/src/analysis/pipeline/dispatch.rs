// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::time::SystemTime;

use bytes::Bytes;

use crate::protocol::identity::TcpHeader;
use crate::protocol::transport::Tcp;

use crate::analysis::conversation_index::CanonicalFlow;
use crate::analysis::pipeline::clock::CaptureClock;
use crate::analysis::pipeline::{Limits, TcpEventRecord};
use crate::analysis::reassembly::tcp::{
    Error as ReassemblyTcpError, Event as TcpEvent, EvictionReason, Reassembler as TcpReassembler,
    Resource as TcpResource, Segment,
};
use crate::analysis::serial::{serial_gt, serial_range_contains};
use crate::analysis::{Error, ScopedFlowKey};

pub(super) struct ReassemblyDispatch {
    tcp_reassembler: Option<TcpReassembler>,
    conversations: HashMap<CanonicalFlow, ConversationMeta>,
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

impl DirectionMeta {
    fn end(&mut self) {
        if self.active
            || self.half_open_pure_syn
            || self.last_syn_base.is_some()
            || self.saw_prior_traffic
            || self.closed
        {
            self.generation = self.generation.saturating_add(1);
        }
        self.active = false;
        self.half_open_pure_syn = false;
        self.saw_prior_traffic = false;
        self.closed = false;
        self.closed_next_sequence = None;
    }

    fn start_syn(&mut self, base: u32) -> bool {
        let retransmitted = self.last_syn_base == Some(base) && (self.active || self.closed);
        let prior_connection = self.active
            || self.half_open_pure_syn
            || self.last_syn_base.is_some()
            || self.saw_prior_traffic
            || self.closed;
        let new_connection = prior_connection && !retransmitted;
        if new_connection {
            self.generation = self.generation.saturating_add(1);
        }
        self.last_syn_base = Some(base);
        self.saw_prior_traffic = false;
        self.closed = false;
        self.closed_next_sequence = None;
        new_connection
    }
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
}

impl ReassemblyDispatch {
    pub(super) fn new(enabled: bool, limits: &Limits) -> Result<Self, Error> {
        let tcp_reassembler = enabled
            .then(|| TcpReassembler::new(limits.tcp.clone()))
            .transpose()?;
        Ok(Self {
            tcp_reassembler,
            conversations: HashMap::new(),
            clock: CaptureClock::new(),
        })
    }

    pub(super) fn generation(&self, flow: &ScopedFlowKey) -> Option<u64> {
        self.conversations
            .get(&CanonicalFlow::from_flow(flow))
            .map(|meta| meta.generation)
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

    fn stamp(&self, event: &TcpEvent) -> TcpEventRecord {
        let flow = event_flow(event);
        let meta = self.conversations.get(&CanonicalFlow::from_flow(flow));
        let direction = meta.and_then(|meta| meta.directions.get(flow));
        TcpEventRecord {
            stream: meta.and_then(|meta| meta.stream).unwrap_or(0),
            generation: meta.map_or(0, |meta| meta.generation),
            direction_generation: direction.map_or(0, |direction| direction.generation),
            event: event.clone(),
        }
    }

    fn emit(
        &mut self,
        event: TcpEvent,
        closed_next_sequence: Option<u32>,
        output: &mut Vec<TcpEventRecord>,
    ) {
        output.push(self.stamp(&event));
        self.observe_event(&event, closed_next_sequence);
    }

    fn observe_event(&mut self, event: &TcpEvent, closed_next_sequence: Option<u32>) {
        let flow = event_flow(event).clone();
        let meta = self.meta(&flow, None);
        match event {
            TcpEvent::Data { .. } => {
                let direction = meta.direction(&flow);
                direction.active = true;
                direction.saw_prior_traffic = true;
            }
            TcpEvent::Evicted { .. } => {
                meta.direction(&flow).end();
            }
            TcpEvent::Closed { reset, .. } => {
                let direction = meta.direction(&flow);
                direction.active = false;
                direction.half_open_pure_syn = false;
                direction.closed = true;
                direction.closed_next_sequence = if *reset { None } else { closed_next_sequence };
            }
            TcpEvent::Retransmission { .. } | TcpEvent::Gap { .. } => {}
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
            for event in expired {
                self.emit(event, None, &mut output);
            }
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
        let mut output = Vec::new();
        let reused = self.evict_reused_generation(segment, acknowledgment, &mut output);
        if segment.syn {
            let base = segment.sequence.wrapping_add(1);
            let meta = self.meta(&segment.flow, None);
            meta.direction(&segment.flow).start_syn(base);
            if reused {
                meta.generation = meta.generation.saturating_add(1);
            }
        }

        let mut input = if segment.rst {
            for flow in [segment.flow.reverse(), segment.flow.clone()] {
                let events = self
                    .tcp_reassembler
                    .as_mut()
                    .expect("reassembler exists")
                    .evict_flow(&flow, EvictionReason::Reset);
                for event in events {
                    self.emit(event, None, &mut output);
                }
            }
            Segment {
                payload: Bytes::new(),
                ..segment.clone()
            }
        } else {
            segment.clone()
        };

        let keep = input.syn || self.trim_post_fin_retransmission(&mut input);
        if !keep {
            return Ok(output);
        }
        let produced = self.push_with_retry(input.clone(), now, number, &mut output)?;
        self.observe_segment(
            &input,
            &produced,
            acknowledgment.is_none() && segment.payload.is_empty(),
        );
        Ok(output)
    }

    fn final_next_sequence(&self, segment: &Segment) -> Option<u32> {
        if segment.fin {
            Some(
                segment
                    .sequence
                    .wrapping_add(u32::from(segment.syn))
                    .wrapping_add(segment.payload.len() as u32)
                    .wrapping_add(1),
            )
        } else {
            self.tcp_reassembler
                .as_ref()
                .and_then(|reassembler| reassembler.flow_final_next_sequence(&segment.flow))
        }
    }

    fn push_with_retry(
        &mut self,
        segment: Segment,
        now: std::time::Instant,
        number: u64,
        output: &mut Vec<TcpEventRecord>,
    ) -> Result<Vec<TcpEvent>, Error> {
        let final_next_sequence = self.final_next_sequence(&segment);
        let first = {
            let reassembler = self.tcp_reassembler.as_mut().expect("reassembler exists");
            reassembler.push(segment.clone(), now)
        };
        match first {
            Ok(produced) => {
                for event in produced.clone() {
                    self.emit(event, final_next_sequence, output);
                }
                Ok(produced)
            }
            Err(ReassemblyTcpError::Resource(
                TcpResource::FlowByteLimit { .. }
                | TcpResource::SegmentLimit { .. }
                | TcpResource::AggregateByteLimit { .. },
            )) => {
                let evicted = {
                    let reassembler = self.tcp_reassembler.as_mut().expect("reassembler exists");
                    reassembler.evict_flow(&segment.flow, EvictionReason::Budget)
                };
                for event in evicted {
                    self.emit(event, None, output);
                }
                let produced = {
                    let reassembler = self.tcp_reassembler.as_mut().expect("reassembler exists");
                    reassembler.push(segment, now)
                }
                .map_err(|source| Error::Reassembly { number, source })?;
                for event in produced.clone() {
                    self.emit(event, final_next_sequence, output);
                }
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
        let reverse_half_open = self
            .conversations
            .get(&CanonicalFlow::from_flow(&segment.flow))
            .and_then(|meta| meta.directions.get(&reverse))
            .is_some_and(|direction| direction.half_open_pure_syn);
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
        let reuse = match own_base {
            Some(base) => {
                base != first
                    || acknowledgment_disagrees
                    || (acknowledgment.is_none()
                        && segment.payload.is_empty()
                        && reassembler.flow_observed_payload(&segment.flow))
            }
            None if acknowledgment.is_some() => acknowledgment_disagrees,
            None => {
                !reverse_half_open
                    && self
                        .conversations
                        .get(&CanonicalFlow::from_flow(&segment.flow))
                        .and_then(|meta| meta.directions.get(&segment.flow))
                        .is_some_and(|direction| direction.last_syn_base.is_some())
            }
        };
        if !reuse {
            return false;
        }
        let mut evictions = Vec::new();
        if reverse_verdict != Some(true) {
            evictions.extend(reassembler.evict_flow(&reverse, EvictionReason::Reuse));
        }
        if own_base.is_some() {
            evictions.extend(reassembler.evict_flow(&segment.flow, EvictionReason::Reuse));
        }
        for event in evictions {
            self.emit(event, None, output);
        }
        true
    }

    fn trim_post_fin_retransmission(&mut self, segment: &mut Segment) -> bool {
        let Some(direction) = self
            .conversations
            .get(&CanonicalFlow::from_flow(&segment.flow))
            .and_then(|meta| meta.directions.get(&segment.flow))
        else {
            return true;
        };
        if !direction.closed || direction.active {
            return true;
        }
        let Some(edge) = direction.closed_next_sequence else {
            return true;
        };
        let start = segment.sequence;
        if !serial_gt(edge, start) {
            return true;
        }
        let overlap = usize::try_from(edge.wrapping_sub(start)).unwrap_or(usize::MAX);
        let fin = usize::from(segment.fin);
        let Some(span) = segment.payload.len().checked_add(fin) else {
            return true;
        };
        if overlap >= span {
            return false;
        }
        let payload_overlap = overlap.min(segment.payload.len());
        if payload_overlap != 0 {
            segment.sequence = segment.sequence.wrapping_add(payload_overlap as u32);
            segment.payload = segment.payload.slice(payload_overlap..);
        }
        if overlap > segment.payload.len() {
            segment.fin = false;
        }
        !segment.payload.is_empty() || segment.fin || segment.rst
    }

    fn observe_segment(&mut self, segment: &Segment, produced: &[TcpEvent], pure_syn: bool) {
        let meta = self.meta(&segment.flow, None);
        let direction = meta.direction(&segment.flow);
        direction.half_open_pure_syn = pure_syn;
        direction.active = true;
        direction.saw_prior_traffic |= !segment.payload.is_empty()
            || produced
                .iter()
                .any(|event| matches!(event, TcpEvent::Data { .. }));
        for event in produced {
            if matches!(event, TcpEvent::Closed { flow, .. } if flow == &segment.flow) {
                direction.active = false;
            }
        }
    }

    pub(super) fn flush(&mut self) -> Vec<TcpEventRecord> {
        let events = self
            .tcp_reassembler
            .as_mut()
            .map(TcpReassembler::flush)
            .unwrap_or_default();
        let mut output = Vec::new();
        for event in events {
            self.emit(event, None, &mut output);
        }
        output
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

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::analysis::FlowKey;
    use crate::analysis::scope::Interner;

    fn flow() -> ScopedFlowKey {
        ScopedFlowKey {
            scope: Interner::default().intern(None, Vec::new()).unwrap(),
            flow: FlowKey {
                source: "192.0.2.1".parse().unwrap(),
                source_port: 40000,
                destination: "192.0.2.2".parse().unwrap(),
                destination_port: 80,
            },
        }
    }

    fn segment(
        flow: &ScopedFlowKey,
        sequence: u32,
        payload: &[u8],
        syn: bool,
        fin: bool,
    ) -> Segment {
        Segment {
            flow: flow.clone(),
            sequence,
            payload: Bytes::copy_from_slice(payload),
            sources: None,
            syn,
            fin,
            rst: false,
        }
    }

    fn data_generation(events: &[TcpEventRecord]) -> Option<u64> {
        events.iter().find_map(|record| match &record.event {
            TcpEvent::Data { .. } => Some(record.generation),
            _ => None,
        })
    }

    #[test]
    fn fast_open_reuse_keeps_one_handshake_generation() {
        let client = flow();
        let server = client.reverse();
        let now = Instant::now();
        let mut dispatch = ReassemblyDispatch::new(true, &Limits::default()).unwrap();
        let mut output = Vec::new();

        for (flow, sequence, acknowledgment, syn, fin) in [
            (&client, 100, None, true, false),
            (&server, 200, Some(101), true, false),
            (&client, 101, Some(201), false, true),
            (&server, 201, Some(102), false, true),
        ] {
            dispatch
                .dispatch_segment(
                    acknowledgment,
                    &segment(flow, sequence, &[], syn, fin),
                    now,
                    1,
                )
                .unwrap();
        }

        let request = b"GET / HTTP/1.1\r\nhost: example\r\n\r\n";
        let events = dispatch
            .dispatch_segment(None, &segment(&client, 500, request, true, false), now, 2)
            .unwrap();
        output.extend(events);
        let client_generation = data_generation(&output).unwrap();
        let response = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        let acknowledgment = 501u32.wrapping_add(request.len() as u32);
        let events = dispatch
            .dispatch_segment(
                Some(acknowledgment),
                &segment(&server, 900, response, true, false),
                now,
                3,
            )
            .unwrap();

        assert_eq!(client_generation, 1);
        assert_eq!(data_generation(&events), Some(client_generation));
    }
}
