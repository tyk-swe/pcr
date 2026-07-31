// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, deadline-bounded response candidate selection.

use std::time::{Duration, SystemTime};

use packetcraftr_packet::decode::Result as DecodedPacket;

pub(crate) fn response_within_deadline(
    latency: Option<Duration>,
    captured_at: SystemTime,
    sent_at: SystemTime,
    timeout: Duration,
) -> bool {
    match latency {
        Some(latency) => latency <= timeout,
        None => captured_at
            .duration_since(sent_at)
            .is_ok_and(|captured_latency| captured_latency <= timeout),
    }
}

pub(crate) fn preferred_latency(candidate: Option<Duration>, current: Option<Duration>) -> bool {
    match (candidate, current) {
        (Some(candidate), Some(current)) => candidate < current,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

pub(crate) struct ResponseCandidate<'a, O> {
    pub(crate) observation: O,
    pub(crate) decoded: &'a DecodedPacket,
    pub(crate) latency: Option<Duration>,
}

pub(crate) fn select_response_candidate<'a, O, K: Ord>(
    best: &mut Option<ResponseCandidate<'a, O>>,
    candidate: ResponseCandidate<'a, O>,
    sent_at: SystemTime,
    timeout: Duration,
    rank: impl Fn(&O) -> u8,
    tie_break_key: impl Fn(&O) -> K,
) -> bool {
    if !response_within_deadline(
        candidate.latency,
        candidate.decoded.frame.timestamp,
        sent_at,
        timeout,
    ) {
        return false;
    }
    let candidate_precedes = best.as_ref().is_none_or(|current| {
        let candidate_rank = rank(&candidate.observation);
        let current_rank = rank(&current.observation);
        if candidate_rank != current_rank {
            return candidate_rank > current_rank;
        }
        if candidate.decoded.frame.timestamp != current.decoded.frame.timestamp {
            return candidate.decoded.frame.timestamp < current.decoded.frame.timestamp;
        }
        let candidate_key = tie_break_key(&candidate.observation);
        let current_key = tie_break_key(&current.observation);
        if candidate_key != current_key {
            return candidate_key < current_key;
        }
        if candidate.decoded.frame.bytes() != current.decoded.frame.bytes() {
            return candidate.decoded.frame.bytes() < current.decoded.frame.bytes();
        }
        preferred_latency(candidate.latency, current.latency)
    });
    if candidate_precedes {
        *best = Some(candidate);
    }
    candidate_precedes
}
