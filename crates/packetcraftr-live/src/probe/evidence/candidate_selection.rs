// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, deadline-bounded response candidate selection.

use std::iter::Peekable;
use std::slice::Iter;
use std::time::Duration;

use packetcraftr_packet::decode::Result as DecodedPacket;

use super::exact_validation::MatchedResponseEvidence;

pub(crate) fn response_within_deadline(latency: Duration, timeout: Duration) -> bool {
    latency <= timeout
}

pub(crate) fn preferred_latency(candidate: Duration, current: Duration) -> bool {
    candidate < current
}

pub(crate) struct ResponseCandidate<'a, O> {
    pub(crate) observation: O,
    pub(crate) decoded: &'a DecodedPacket,
    pub(crate) latency: Duration,
}

pub(crate) fn select_response_candidate<'a, O, K: Ord>(
    best: &mut Option<ResponseCandidate<'a, O>>,
    candidate: ResponseCandidate<'a, O>,
    timeout: Duration,
    rank: impl Fn(&O) -> u8,
    tie_break_key: impl Fn(&O) -> K,
) -> bool {
    if !response_within_deadline(candidate.latency, timeout) {
        return false;
    }
    let candidate_precedes = best.as_ref().is_none_or(|current| {
        let candidate_rank = rank(&candidate.observation);
        let current_rank = rank(&current.observation);
        if candidate_rank != current_rank {
            return candidate_rank > current_rank;
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

/// Stable, linear-time response grouping shared by every bounded probe batch.
/// Sorting is stable so equal request indices preserve executor evidence order.
pub(crate) struct ResponseSelector<'a, M> {
    matched: Peekable<Iter<'a, M>>,
}

impl<'a, M: MatchedResponseEvidence> ResponseSelector<'a, M> {
    pub(crate) fn new(matched: &'a mut [M]) -> Self {
        matched.sort_by_key(MatchedResponseEvidence::request_index);
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
            .is_some_and(|response| response.request_index() == request_index)
        {
            check_deadline()?;
            let response = self
                .matched
                .next()
                .expect("peeked matched response must remain available");
            if let Some(observation) = classify(response.response())
                && select_response_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: response.response(),
                        latency: response.latency(),
                    },
                    timeout,
                    &rank,
                    &tie_break_key,
                )
            {}
            check_deadline()?;
        }
        Ok(best)
    }
}
