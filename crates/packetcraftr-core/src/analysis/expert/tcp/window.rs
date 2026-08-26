// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use crate::diagnostic::Severity;

use super::super::finding::new as new_finding;
use super::super::observation::TcpObservation;
use super::super::{Finding, FlowKey};
use super::DirectionState;

pub(super) fn report_zero(observation: &TcpObservation<'_>, findings: &mut Vec<Finding>) {
    if observation.tcp.window == 0 && !observation.rst {
        findings.push(new_finding(
            Severity::Warning,
            "tcp.zero_window",
            observation.number,
            observation.stream,
            format!(
                "{}:{} advertises a zero receive window",
                observation.flow.flow.source, observation.flow.flow.source_port
            ),
        ));
    }
}

pub(super) fn update_advertisement(
    flows: &mut HashMap<FlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
) {
    let TcpObservation { flow, tcp, syn, .. } = *observation;
    let sent = flows.entry(flow.clone()).or_default();
    // SND.WL1/WL2 compare sequence and acknowledgment with serial arithmetic.
    let window_update = match (sent.window_sequence, sent.window_acknowledgment) {
        (Some(update_sequence), Some(update_acknowledgment)) => {
            let sequence_delta = tcp.sequence.wrapping_sub(update_sequence);
            (sequence_delta > 0 && sequence_delta < 0x8000_0000)
                || (tcp.sequence == update_sequence
                    && tcp.acknowledgment.wrapping_sub(update_acknowledgment) < 0x8000_0000)
        }
        _ => true,
    };
    if window_update {
        sent.window = Some(tcp.window);
        sent.window_sequence = Some(tcp.sequence);
        sent.window_acknowledgment = Some(tcp.acknowledgment);
        sent.window_from_syn = syn;
    }
}

pub(super) fn analyze_sender(
    flows: &HashMap<FlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
    reverse: &FlowKey,
    keep_alive: bool,
    findings: &mut Vec<Finding>,
) {
    let TcpObservation {
        number,
        stream,
        flow,
        tcp,
        payload_len,
        syn,
        fin,
        rst,
        ..
    } = *observation;
    if (payload_len == 0 && !fin) || keep_alive || rst {
        return;
    }
    let Some(peer) = flows.get(reverse).copied() else {
        return;
    };
    let (Some(peer_ack), Some(peer_window)) = (peer.acknowledgment, peer.window) else {
        return;
    };

    let end = tcp.sequence.wrapping_add(
        u32::try_from(payload_len)
            .unwrap_or(u32::MAX)
            .saturating_add(u32::from(syn))
            .saturating_add(u32::from(fin)),
    );
    let in_flight = end.wrapping_sub(peer_ack);
    let handshake_seen = peer.syn_seen && flows.get(flow).is_some_and(|sender| sender.syn_seen);
    let shift = match (
        flows.get(flow).and_then(|sender| sender.window_shift),
        peer.window_shift,
    ) {
        (Some(_), Some(peer_shift)) if !peer.window_from_syn => u32::from(peer_shift.min(14)),
        _ => 0,
    };
    let advertised = u64::from(peer_window) << shift;
    if in_flight >= 0x8000_0000 {
        return;
    }

    if peer_window == 0 {
        if in_flight > 0 {
            if payload_len == 1 && !fin && in_flight == 1 {
                findings.push(new_finding(
                    Severity::Info,
                    "tcp.zero_window_probe",
                    number,
                    stream,
                    format!(
                        "{}:{} probes the peer's zero receive window",
                        flow.flow.source, flow.flow.source_port
                    ),
                ));
            } else {
                findings.push(new_finding(
                    Severity::Warning,
                    "tcp.window_exceeded",
                    number,
                    stream,
                    format!(
                        "{}:{} has sent {} byte(s) beyond the peer's zero receive window",
                        flow.flow.source,
                        flow.flow.source_port,
                        u64::from(in_flight)
                    ),
                ));
            }
        }
    } else if handshake_seen && u64::from(in_flight) == advertised {
        findings.push(new_finding(
            Severity::Warning,
            "tcp.window_full",
            number,
            stream,
            format!(
                "{}:{} has filled the peer's {advertised}-byte receive window",
                flow.flow.source, flow.flow.source_port
            ),
        ));
    } else if handshake_seen && u64::from(in_flight) > advertised {
        findings.push(new_finding(
            Severity::Warning,
            "tcp.window_exceeded",
            number,
            stream,
            format!(
                "{}:{} has sent {} byte(s) beyond the peer's {advertised}-byte receive window",
                flow.flow.source,
                flow.flow.source_port,
                u64::from(in_flight).saturating_sub(advertised)
            ),
        ));
    }
}

pub(super) fn scale(options: &[u8]) -> Option<u8> {
    let mut rest = options;
    loop {
        match rest {
            [] | [0, ..] => return None,
            [1, tail @ ..] => rest = tail,
            [3, 3, shift, ..] => return Some(*shift),
            [_, length, tail @ ..] if *length >= 2 => {
                rest = tail.get(usize::from(*length).checked_sub(2)?..)?;
            }
            _ => return None,
        }
    }
}
