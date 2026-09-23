// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, deadline-bounded response candidate selection.

use std::iter::Peekable;
use std::slice::Iter;
use std::time::Duration;

use packetcraftr_core::decode::DecodedPacket;

use crate::exchange::Response;

pub(crate) fn response_within_deadline(latency: Duration, timeout: Duration) -> bool {
    latency <= timeout
}

fn preferred_latency(candidate: Duration, current: Duration) -> bool {
    candidate < current
}

pub(crate) struct ResponseCandidate<'a, O> {
    pub(crate) observation: O,
    pub(crate) decoded: &'a DecodedPacket,
    pub(crate) latency: Duration,
}

/// What the one candidate ordering compares about a response. Serial batch
/// selection builds it from each [`ResponseCandidate`]; a pipelined executor
/// that keeps a best-so-far response builds it from what it retained.
pub(crate) struct CandidateKey<'a, K> {
    /// Higher wins.
    pub(crate) rank: u8,
    /// Breaks rank ties; lower wins. Probe workflows use the responder.
    pub(crate) tie_break: K,
    /// Breaks key ties; shorter wins.
    pub(crate) latency: Duration,
    /// Breaks latency ties; the lexicographically lower exact frame wins.
    pub(crate) bytes: &'a [u8],
}

/// The single tie-break rule: rank, then tie-break key (responder), then
/// latency, then bytes. A complete tie keeps the current candidate, so equal
/// evidence never depends on arrival order.
pub(crate) fn candidate_precedes<K: Ord>(
    candidate: &CandidateKey<'_, K>,
    current: &CandidateKey<'_, K>,
) -> bool {
    if candidate.rank != current.rank {
        return candidate.rank > current.rank;
    }
    if candidate.tie_break != current.tie_break {
        return candidate.tie_break < current.tie_break;
    }
    if candidate.latency != current.latency {
        return preferred_latency(candidate.latency, current.latency);
    }
    candidate.bytes < current.bytes
}

pub(crate) fn update_best_candidate<'a, O, K: Ord>(
    best: &mut Option<ResponseCandidate<'a, O>>,
    candidate: ResponseCandidate<'a, O>,
    timeout: Duration,
    rank: impl Fn(&O) -> u8,
    tie_break_key: impl Fn(&O) -> K,
) {
    if !response_within_deadline(candidate.latency, timeout) {
        return;
    }
    let key = |candidate: &ResponseCandidate<'a, O>| CandidateKey {
        rank: rank(&candidate.observation),
        tie_break: tie_break_key(&candidate.observation),
        latency: candidate.latency,
        bytes: candidate.decoded.frame.bytes().as_ref(),
    };
    let candidate_precedes = best
        .as_ref()
        .is_none_or(|current| candidate_precedes(&key(&candidate), &key(current)));
    if candidate_precedes {
        *best = Some(candidate);
    }
}

/// Stable, linear-time response grouping shared by every bounded probe batch.
/// Sorting is stable so equal request indices preserve executor evidence order.
pub(crate) struct ResponseSelector<'a> {
    matched: Peekable<Iter<'a, Response>>,
}

impl<'a> ResponseSelector<'a> {
    pub(crate) fn new(matched: &'a mut [Response]) -> Self {
        matched.sort_by_key(|response| response.request_index);
        Self {
            matched: matched.iter().peekable(),
        }
    }

    pub(crate) fn select<O, K: Ord, E>(
        &mut self,
        request_index: usize,
        timeout: Duration,
        mut classify: impl FnMut(&DecodedPacket) -> Option<O>,
        rank: impl Fn(&O) -> u8,
        tie_break_key: impl Fn(&O) -> K,
        mut check_deadline: impl FnMut() -> Result<(), E>,
    ) -> Result<Option<ResponseCandidate<'a, O>>, E> {
        let mut best = None;
        while self
            .matched
            .peek()
            .is_some_and(|response| response.request_index == request_index)
        {
            check_deadline()?;
            let response = self
                .matched
                .next()
                .expect("peeked matched response must remain available");
            if let Some(observation) = classify(&response.response) {
                update_best_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: &response.response,
                        latency: response.latency,
                    },
                    timeout,
                    &rank,
                    &tie_break_key,
                );
            }
            check_deadline()?;
        }
        Ok(best)
    }
}
