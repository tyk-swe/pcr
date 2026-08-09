// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, deadline-bounded response candidate selection.

use std::collections::HashSet;
use std::iter::Peekable;
use std::slice::Iter;
use std::time::{Duration, Instant, SystemTime};

use crate::exchange::UnsolicitedResponse;
use packetcraftr_network::capture::CaptureRecordId;
use packetcraftr_packet::decode::Result as DecodedPacket;

use super::exact_validation::MatchedResponseEvidence;

pub(crate) fn response_within_deadline(
    latency: Option<Duration>,
    captured_at: Option<Instant>,
    sent_at: Instant,
    timeout: Duration,
) -> bool {
    let Some(captured_at) = captured_at else {
        return false;
    };
    let Some(captured_latency) = captured_at.checked_duration_since(sent_at) else {
        return false;
    };
    latency.is_none_or(|latency| latency == captured_latency) && captured_latency <= timeout
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
    pub(crate) captured_at: Option<Instant>,
}

pub(crate) fn select_response_candidate<'a, O, K: Ord>(
    best: &mut Option<ResponseCandidate<'a, O>>,
    candidate: ResponseCandidate<'a, O>,
    sent_at: Instant,
    timeout: Duration,
    sent_wall: Option<SystemTime>,
    rank: impl Fn(&O) -> u8,
    tie_break_key: impl Fn(&O) -> K,
) -> bool {
    if !response_within_deadline(candidate.latency, candidate.captured_at, sent_at, timeout) {
        return false;
    }
    if let (Some(sent_wall), Some(received_wall)) = (sent_wall, candidate.decoded.frame.timestamp)
        && received_wall < sent_wall
    {
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
    unsolicited: &'a [UnsolicitedResponse],
    consumed_unsolicited: HashSet<CaptureRecordId>,
}

impl<'a, M: MatchedResponseEvidence> ResponseSelector<'a, M> {
    pub(crate) fn new(matched: &'a mut [M], unsolicited: &'a [UnsolicitedResponse]) -> Self {
        matched.sort_by_key(MatchedResponseEvidence::request_index);
        Self {
            matched: matched.iter().peekable(),
            unsolicited,
            consumed_unsolicited: HashSet::new(),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the selection seam threads request identity, timing, and the caller's fallible \
                  callbacks; a parameter struct would only rename the same fields"
    )]
    pub(crate) fn select<O, K: Ord, E>(
        &mut self,
        request_index: usize,
        sent_at: Instant,
        timeout: Duration,
        sent_wall: Option<SystemTime>,
        mut classify: impl FnMut(&DecodedPacket) -> Option<O>,
        rank: impl Fn(&O) -> u8,
        tie_break_key: impl Fn(&O) -> K,
        mut check_deadline: impl FnMut() -> Result<(), E>,
    ) -> Result<Option<ResponseCandidate<'a, O>>, E> {
        let mut best = None;
        let mut best_unsolicited = None;
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
                        latency: Some(response.latency()),
                        captured_at: Some(response.received_at()),
                    },
                    sent_at,
                    timeout,
                    sent_wall,
                    &rank,
                    &tie_break_key,
                )
            {
                best_unsolicited = None;
            }
            check_deadline()?;
        }
        for response in self.unsolicited {
            if !response.workflow_eligible()
                || self.consumed_unsolicited.contains(&response.record_id())
            {
                continue;
            }
            check_deadline()?;
            if let Some(observation) = classify(response.response())
                && select_response_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: response.response(),
                        latency: response
                            .received_at()
                            .and_then(|captured| captured.checked_duration_since(sent_at)),
                        captured_at: response.received_at(),
                    },
                    sent_at,
                    timeout,
                    sent_wall,
                    &rank,
                    &tie_break_key,
                )
            {
                best_unsolicited = Some(response.record_id());
            }
            check_deadline()?;
        }
        if let Some(record_id) = best_unsolicited {
            self.consumed_unsolicited.insert(record_id);
        }
        Ok(best)
    }
}
