// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Reassembly dispatch and stream tracking over the analysis pipeline.

use std::collections::HashSet;
use std::time::SystemTime;

use crate::decode::DecodedPacket;
use crate::protocol::transport::Tcp;
use bytes::Bytes;

use crate::analysis::Error;
use crate::analysis::adapter::transports;
use crate::analysis::pipeline::clock::CaptureClock;
use crate::analysis::reassembly::Limits as TcpReassemblyLimits;
use crate::analysis::reassembly::tcp::{
    Error as ReassemblyTcpError, Event as TcpEvent, Reassembler as TcpReassembler, ScopedFlowKey,
    Segment,
};

pub(super) struct ReassemblyDispatch {
    tcp_reassembler: Option<TcpReassembler>,
    half_open_pure_syns: HashSet<ScopedFlowKey>,
}

impl ReassemblyDispatch {
    pub(super) fn new(enabled: bool, max_flows: usize) -> Self {
        let tcp_reassembler = enabled.then(|| {
            TcpReassembler::new(TcpReassemblyLimits {
                max_flows: max_flows.saturating_mul(2),
                ..TcpReassemblyLimits::default()
            })
        });
        Self {
            tcp_reassembler,
            half_open_pure_syns: HashSet::new(),
        }
    }

    pub(super) fn dispatch(
        &mut self,
        decoded: &DecodedPacket,
        segment: Option<&Segment>,
        timestamp: SystemTime,
        number: u64,
        clock: &mut CaptureClock,
        max_flows: usize,
    ) -> Result<Vec<TcpEvent>, Error> {
        let mut tcp_events = Vec::new();
        let Some(reassembler) = &mut self.tcp_reassembler else {
            return Ok(tcp_events);
        };

        let now = clock.at(timestamp, number)?;
        let sweep_due = clock.should_sweep(now);
        let pushable = segment.as_ref().is_some_and(|segment| {
            !segment.payload.is_empty() || segment.syn || segment.fin || segment.rst
        });

        if pushable || sweep_due {
            tcp_events.extend(reassembler.expire(now));
            clear_closed_flows(&mut self.half_open_pure_syns, &tcp_events);
        }

        if pushable && let Some(segment) = segment {
            tcp_events.extend(dispatch_segment(
                reassembler,
                &mut self.half_open_pure_syns,
                decoded,
                segment,
                now,
                number,
                max_flows,
            )?);
        }

        Ok(tcp_events)
    }

    pub(super) fn flush(&mut self) -> Vec<TcpEvent> {
        self.tcp_reassembler
            .as_mut()
            .map(TcpReassembler::flush)
            .unwrap_or_default()
    }
}

fn dispatch_segment(
    reassembler: &mut TcpReassembler,
    half_open_pure_syns: &mut HashSet<ScopedFlowKey>,
    decoded: &DecodedPacket,
    segment: &Segment,
    now: std::time::Instant,
    number: u64,
    max_flows: usize,
) -> Result<Vec<TcpEvent>, Error> {
    let acknowledgment = transports(&decoded.packet)
        .tcp
        .filter(|transport| transport.layer.flags & Tcp::ACK != 0)
        .map(|transport| transport.layer.acknowledgment);
    let flow = segment.flow.clone();
    let pure_syn = segment.syn && acknowledgment.is_none() && segment.payload.is_empty();
    let mut events = Vec::new();
    evict_reused_generation(
        reassembler,
        half_open_pure_syns,
        segment,
        acknowledgment,
        &mut events,
    );
    let segment = if segment.rst {
        events.extend(reassembler.evict_flow(&segment.flow.reverse()));
        events.extend(reassembler.evict_flow(&segment.flow));
        Segment {
            payload: Bytes::new(),
            ..segment.clone()
        }
    } else {
        segment.clone()
    };
    push_with_retry(reassembler, segment, now, number, &mut events)?;
    clear_closed_flows(half_open_pure_syns, &events);
    if pure_syn && half_open_pure_syns.len() < max_flows.saturating_mul(2) {
        half_open_pure_syns.insert(flow);
    } else if !pure_syn {
        half_open_pure_syns.remove(&flow);
    }
    Ok(events)
}

fn evict_reused_generation(
    reassembler: &mut TcpReassembler,
    half_open_pure_syns: &HashSet<ScopedFlowKey>,
    segment: &Segment,
    acknowledgment: Option<u32>,
    events: &mut Vec<TcpEvent>,
) {
    if !segment.syn {
        return;
    }
    let first = segment.sequence.wrapping_add(1);
    let reverse = segment.flow.reverse();
    let reverse_verdict = acknowledgment.and_then(|acknowledgment| {
        match (
            reassembler.flow_base_sequence(&reverse),
            reassembler.flow_next_sequence(&reverse),
        ) {
            (Some(base), Some(next)) => Some(
                acknowledgment.wrapping_sub(base) < 0x8000_0000
                    && next.wrapping_sub(acknowledgment) < 0x8000_0000,
            ),
            _ => None,
        }
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
        None => !half_open_pure_syns.contains(&reverse),
    };
    if reuse {
        if reverse_verdict != Some(true) {
            events.extend(reassembler.evict_flow(&reverse));
        }
        if own_base.is_some() {
            events.extend(reassembler.evict_flow(&segment.flow));
        }
    }
}

fn push_with_retry(
    reassembler: &mut TcpReassembler,
    segment: Segment,
    now: std::time::Instant,
    number: u64,
    events: &mut Vec<TcpEvent>,
) -> Result<(), Error> {
    match reassembler.push(segment.clone(), now) {
        Ok(produced) => events.extend(produced),
        Err(
            ReassemblyTcpError::FlowByteLimit { .. }
            | ReassemblyTcpError::SegmentLimit { .. }
            | ReassemblyTcpError::AggregateByteLimit { .. },
        ) => {
            events.extend(reassembler.evict_flow(&segment.flow));
            events.extend(
                reassembler
                    .push(segment, now)
                    .map_err(|source| Error::Reassembly { number, source })?,
            );
        }
        Err(source) => return Err(Error::Reassembly { number, source }),
    }
    Ok(())
}

fn clear_closed_flows(half_open_pure_syns: &mut HashSet<ScopedFlowKey>, events: &[TcpEvent]) {
    for event in events {
        if let TcpEvent::Closed { flow, .. } | TcpEvent::Evicted { flow, .. } = event {
            half_open_pure_syns.remove(flow);
        }
    }
}
