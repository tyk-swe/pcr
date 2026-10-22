// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, deadline-bounded response candidate selection.

use std::iter::Peekable;
use std::slice::Iter;
use std::time::Duration;

use packetcraftr_core::decode::DecodedPacket;

use super::Response;

fn response_within_deadline(latency: Duration, timeout: Duration) -> bool {
    latency <= timeout
}

fn preferred_latency(candidate: Duration, current: Duration) -> bool {
    candidate < current
}

/// Why a matched response did not become its probe's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Passed {
    /// It arrived after the probe's deadline.
    Late,
    /// A higher-ranked or earlier response was kept instead.
    Superseded,
}

pub(crate) struct ResponseCandidate<'a, O> {
    pub(crate) observation: O,
    pub(crate) decoded: &'a DecodedPacket,
    pub(crate) latency: Duration,
}

pub(crate) struct CandidateKey<'a, T> {
    /// Higher wins.
    pub(crate) rank: u8,
    /// Breaks rank ties; lower wins.
    pub(crate) tie_break: T,
    /// Breaks key ties; shorter wins.
    pub(crate) latency: Duration,
    /// Breaks latency ties; the lexicographically lower exact frame wins.
    pub(crate) bytes: &'a [u8],
}

pub(crate) fn candidate_precedes<T: Ord>(
    candidate: &CandidateKey<'_, T>,
    current: &CandidateKey<'_, T>,
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

/// Returns the response that lost, if any, and why.
fn update_best_candidate<'a, O, K: Ord>(
    best: &mut Option<ResponseCandidate<'a, O>>,
    candidate: ResponseCandidate<'a, O>,
    timeout: Duration,
    rank: impl Fn(&O) -> u8,
    tie_break_key: impl Fn(&O) -> K,
) -> Option<(&'a DecodedPacket, Passed)> {
    if !response_within_deadline(candidate.latency, timeout) {
        return Some((candidate.decoded, Passed::Late));
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
        best.replace(candidate)
            .map(|previous| (previous.decoded, Passed::Superseded))
    } else {
        Some((candidate.decoded, Passed::Superseded))
    }
}

/// One request's selection: the response that became its outcome, if any,
/// and every other classified response, in executor evidence order, with why
/// it did not.
pub(crate) struct Selected<'a, O> {
    pub(crate) best: Option<ResponseCandidate<'a, O>>,
    pub(crate) passed: Vec<(&'a DecodedPacket, Passed)>,
}

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

    /// Selects request `request_index`'s outcome from its matched responses.
    pub(crate) fn select<O, K: Ord, E>(
        &mut self,
        request_index: usize,
        timeout: Duration,
        mut classify: impl FnMut(&DecodedPacket) -> Option<O>,
        rank: impl Fn(&O) -> u8,
        tie_break_key: impl Fn(&O) -> K,
        mut check_deadline: impl FnMut() -> Result<(), E>,
    ) -> Result<Selected<'a, O>, E> {
        let mut best = None;
        let mut passed = Vec::new();
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
            if let Some(observation) = classify(&response.response)
                && let Some(lost) = update_best_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: &response.response,
                        latency: response.latency,
                    },
                    timeout,
                    &rank,
                    &tie_break_key,
                )
            {
                passed.push(lost);
            }
            check_deadline()?;
        }
        Ok(Selected { best, passed })
    }
}
