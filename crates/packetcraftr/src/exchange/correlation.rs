// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Timestamped response correlation and workflow promotion.

use std::time::Instant;

use packetcraftr_core::{
    decode::DecodedPacket, diagnostic::Diagnostic, frame::Frame, matcher::Match, registry::Registry,
};
use packetcraftr_netio::{
    capture::{Captured, RecordIdentity},
    transmit::Timing,
};

use super::accumulator::{
    Accumulator, DuplicateRecord, ProcessContext, ProcessOutcome, UnsolicitedEvidence,
    UnsolicitedFreshness, WorkflowResponseMatcher,
};
use super::contract::{Options, Response};
use crate::materialize::PreparedPacket;
use crate::planning::expired;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attribution {
    None,
    Unique(usize),
    Ambiguous,
}

struct CorrelationDeadlineExpired;

fn attribution(winners: &[usize]) -> Attribution {
    match winners {
        [] => Attribution::None,
        [request_index] => Attribution::Unique(*request_index),
        _ => Attribution::Ambiguous,
    }
}

fn capture_follows_send(received_at: Instant, timing: Timing) -> bool {
    received_at >= timing.freshness_marker().monotonic()
}

fn ensure_correlation_active(deadline: Instant) -> Result<(), CorrelationDeadlineExpired> {
    if expired(deadline) {
        return Err(CorrelationDeadlineExpired);
    }
    Ok(())
}

fn select_attribution(
    registry: &Registry,
    prepared: &[PreparedPacket],
    sent: &[std::sync::Arc<crate::SentPacket>],
    received_at: Option<Instant>,
    decoded: &DecodedPacket,
    deadline: Instant,
) -> Result<Attribution, CorrelationDeadlineExpired> {
    let mut best_match: Option<Match> = None;
    let mut equally_best = Vec::new();
    for (request_index, prepared_request) in prepared.iter().take(sent.len()).enumerate() {
        ensure_correlation_active(deadline)?;
        let Some(received_at) = received_at else {
            continue;
        };
        #[expect(
            clippy::indexing_slicing,
            reason = "`request_index` comes from an enumerate over `prepared` truncated by \
                      `.take(sent.len())`, so it is below `sent.len()`"
        )]
        let timing = sent[request_index].timing();
        if received_at > deadline || !capture_follows_send(received_at, timing) {
            continue;
        }

        let mut request_match: Option<Match> = None;
        for layer in prepared_request.built.packet.iter() {
            ensure_correlation_active(deadline)?;
            let Some(matcher) = registry.matcher(layer.protocol_id().as_str()) else {
                continue;
            };
            let candidate = matcher.matches(&prepared_request.built.packet, &decoded.packet);
            ensure_correlation_active(deadline)?;
            if let Some(candidate) = candidate
                && request_match.is_none_or(|best| candidate.confidence > best.confidence)
            {
                request_match = Some(candidate);
            }
        }
        ensure_correlation_active(deadline)?;
        let Some(request_match) = request_match else {
            continue;
        };

        let replace = best_match.is_none_or(|best| request_match.confidence > best.confidence);
        if replace {
            equally_best.clear();
            equally_best.push(request_index);
            best_match = Some(request_match);
        } else if best_match.is_some_and(|best| request_match.confidence == best.confidence) {
            equally_best.push(request_index);
        }
    }
    ensure_correlation_active(deadline)?;
    Ok(attribution(&equally_best))
}

impl Accumulator {
    pub(crate) fn process(
        &mut self,
        captured: Captured,
        context: ProcessContext<'_>,
    ) -> Result<ProcessOutcome, DuplicateRecord> {
        let identity = captured.identity();
        if !self.can_retain_record(identity) {
            return Err(DuplicateRecord);
        }
        let Captured {
            frame, received_at, ..
        } = captured;
        if self.correlation_deadline_expired || expired(context.deadline) {
            return Ok(self.retain_capture_after_deadline(identity, frame, context));
        }

        let decoded = match self.decode_capture(identity, frame, context) {
            Ok(decoded) => decoded,
            Err(outcome) => return Ok(outcome),
        };
        Ok(self.correlate_decoded_capture(identity, received_at, decoded, context))
    }

    fn retain_capture_after_deadline(
        &mut self,
        identity: RecordIdentity,
        frame: Frame,
        context: ProcessContext<'_>,
    ) -> ProcessOutcome {
        self.mark_correlation_deadline_expired();
        let raw_frame = frame.clone();
        match context
            .dissector
            .decode(frame, context.options.decode.clone())
        {
            Ok(decoded) => self.retain_unsolicited(identity, decoded, context.options, None),
            Err(_) => self.retain_undecoded(identity, raw_frame, context.options),
        }
        ProcessOutcome::CorrelationDeadlineExpired
    }

    fn decode_capture(
        &mut self,
        identity: RecordIdentity,
        frame: Frame,
        context: ProcessContext<'_>,
    ) -> Result<DecodedPacket, ProcessOutcome> {
        let raw_frame = frame.clone();
        match context
            .dissector
            .decode(frame, context.options.decode.clone())
        {
            Ok(decoded) => {
                if expired(context.deadline) {
                    return Err(self.expire_decoded(identity, decoded, context.options));
                }
                Ok(decoded)
            }
            Err(error) => {
                if expired(context.deadline) {
                    self.mark_correlation_deadline_expired();
                    self.retain_undecoded(identity, raw_frame, context.options);
                    return Err(ProcessOutcome::CorrelationDeadlineExpired);
                }
                self.diagnostics.push_once(Diagnostic::warning(
                    "exchange.decode_error",
                    format!("captured frame could not be decoded: {error}"),
                ));
                self.retain_undecoded(identity, raw_frame, context.options);
                Err(ProcessOutcome::Continue)
            }
        }
    }

    fn correlate_decoded_capture(
        &mut self,
        identity: RecordIdentity,
        received_at: Option<Instant>,
        decoded: DecodedPacket,
        context: ProcessContext<'_>,
    ) -> ProcessOutcome {
        let integrity_failure = decoded
            .diagnostics
            .iter()
            .any(Diagnostic::is_checksum_failure);
        if expired(context.deadline) {
            return self.expire_decoded(identity, decoded, context.options);
        }
        if integrity_failure {
            self.diagnostics.push_once(Diagnostic::warning(
                "exchange.integrity_rejected",
                "a response whose checksum did not verify was not correlated",
            ));
            self.retain_unsolicited(
                identity,
                decoded,
                context.options,
                unsolicited_freshness(received_at, context.sent, context.deadline),
            );
            return ProcessOutcome::Continue;
        }

        if received_at.is_none() {
            self.diagnostics.push_once(
                Diagnostic::warning(
                    "capture.ingress_time_unavailable",
                    "a capture provider returned a frame without an ingress marker; the frame was retained but not correlated",
                ),
            );
        }

        let attribution = match select_attribution(
            context.registry,
            context.prepared,
            context.sent,
            received_at,
            &decoded,
            context.deadline,
        ) {
            Ok(attribution) => attribution,
            Err(CorrelationDeadlineExpired) => {
                return self.expire_decoded(identity, decoded, context.options);
            }
        };
        self.record_attribution(identity, received_at, decoded, attribution, context)
    }

    fn record_attribution(
        &mut self,
        identity: RecordIdentity,
        received_at: Option<Instant>,
        decoded: DecodedPacket,
        attribution: Attribution,
        context: ProcessContext<'_>,
    ) -> ProcessOutcome {
        match attribution {
            Attribution::Ambiguous => {
                self.diagnostics.push_once(
                    Diagnostic::warning(
                        "exchange.ambiguous_attribution",
                        "a captured response matched several requests equally and was retained as unsolicited",
                    ),
                );
                self.retain_unsolicited(
                    identity,
                    decoded,
                    context.options,
                    unsolicited_freshness(received_at, context.sent, context.deadline),
                );
            }
            Attribution::Unique(request_index) => {
                let received_at = received_at.expect("only timestamped capture frames can match");
                if expired(context.deadline) {
                    return self.expire_decoded(identity, decoded, context.options);
                }
                if self.response_count >= context.options.max_responses {
                    self.diagnostics.push_once(Diagnostic::warning(
                        "exchange.response_limit",
                        format!(
                            "matched response limit {} reached; later responses were not retained",
                            context.options.max_responses
                        ),
                    ));
                    return ProcessOutcome::Continue;
                }
                if expired(context.deadline) {
                    return self.expire_decoded(identity, decoded, context.options);
                }
                if self.reserve_decoded_evidence(decoded.original.len(), context.options) {
                    self.mark_record_retained(identity);
                    #[expect(
                        clippy::indexing_slicing,
                        clippy::arithmetic_side_effects,
                        reason = "a unique attribution indexes a request that was already sent, so \
                                  `request_index` is below both `sent.len()` and \
                                  `response_counts.len()`; both counters stay under \
                                  `max_responses`, which is checked just above"
                    )]
                    {
                        self.response_counts[request_index] += 1;
                        self.response_count += 1;
                    }
                    #[expect(
                        clippy::indexing_slicing,
                        reason = "a unique attribution indexes a request that was already sent, so \
                                  `request_index` is below `sent.len()`"
                    )]
                    self.pending_events
                        .push(super::contract::Event::Response(Response {
                            request_index,
                            response: decoded,
                            latency: received_at.duration_since(
                                context.sent[request_index]
                                    .timing()
                                    .freshness_marker()
                                    .monotonic(),
                            ),
                        }));
                }
            }
            Attribution::None => {
                if context.sent.len() < context.prepared.len() {
                    self.diagnostics.push_once(
                        Diagnostic::info(
                            "exchange.pre_send_frame",
                            "a captured frame arrived before one or more requests were sent and was not correlated to those requests",
                        ),
                    );
                }
                self.retain_unsolicited(
                    identity,
                    decoded,
                    context.options,
                    unsolicited_freshness(received_at, context.sent, context.deadline),
                );
            }
        }
        ProcessOutcome::Continue
    }

    pub(crate) fn promote_workflow_unsolicited(
        &mut self,
        context: ProcessContext<'_>,
        matches_request: &mut WorkflowResponseMatcher<'_>,
    ) -> ProcessOutcome {
        let ProcessContext {
            prepared,
            sent,
            deadline,
            options,
            ..
        } = context;
        let max_responses = options.max_responses;
        if self.unsolicited.is_empty() {
            return ProcessOutcome::Continue;
        }
        let mut candidates = std::mem::take(&mut self.unsolicited).into_iter();
        if expired(deadline) {
            return self.expire_workflow_candidates(candidates);
        }

        while let Some(candidate) = candidates.next() {
            if expired(deadline) {
                return self
                    .expire_workflow_candidates(std::iter::once(candidate).chain(candidates));
            }
            let Some(freshness) = candidate.freshness else {
                self.queue_unsolicited(candidate);
                continue;
            };
            if self.workflow_response_limit_reached(max_responses) {
                self.queue_unsolicited(candidate);
                continue;
            }
            let mut winners = Vec::new();
            for (request_index, prepared_request) in prepared
                .iter()
                .enumerate()
                .take(freshness.eligible_requests)
            {
                let matched = matches_request(
                    request_index,
                    &prepared_request.built.packet,
                    &candidate.decoded,
                );
                if expired(deadline) {
                    return self
                        .expire_workflow_candidates(std::iter::once(candidate).chain(candidates));
                }
                if matched {
                    winners.push(request_index);
                }
            }
            let request_index = match attribution(&winners) {
                Attribution::Unique(request_index) => request_index,
                attribution => {
                    if attribution == Attribution::Ambiguous {
                        self.diagnostics.push_once(
                            Diagnostic::warning(
                                "exchange.ambiguous_attribution",
                                "a workflow response matched several requests and was retained as unsolicited",
                            ),
                        );
                    }
                    self.queue_unsolicited(candidate);
                    continue;
                }
            };
            #[expect(
                clippy::indexing_slicing,
                clippy::arithmetic_side_effects,
                reason = "`request_index` is a winner from an enumerate over `prepared` truncated \
                          by `.take(freshness.eligible_requests)`, and `eligible_requests` is a \
                          partition point in `sent`, so it is below `sent.len()` and \
                          `response_counts.len()`; both counters stay under `max_responses`, \
                          which is checked before the candidate is accepted"
            )]
            {
                self.response_counts[request_index] += 1;
                self.response_count += 1;
            }
            self.retained_unmatched = self
                .retained_unmatched
                .checked_sub(1)
                .expect("workflow candidates are retained unmatched evidence");
            #[expect(
                clippy::indexing_slicing,
                reason = "`request_index` is below `freshness.eligible_requests`, a partition \
                          point in `sent`, so it is below `sent.len()`"
            )]
            let sent_timing_monotonic = sent[request_index].timing().freshness_marker().monotonic();
            self.pending_events
                .push(super::contract::Event::Response(Response {
                    request_index,
                    response: candidate.decoded,
                    latency: freshness.received_at.duration_since(sent_timing_monotonic),
                }));
        }
        ProcessOutcome::Continue
    }

    pub(crate) fn finalize_unsolicited(&mut self) {
        for candidate in std::mem::take(&mut self.unsolicited) {
            self.queue_unsolicited(candidate);
        }
    }

    fn expire_workflow_candidates(
        &mut self,
        candidates: impl IntoIterator<Item = UnsolicitedEvidence>,
    ) -> ProcessOutcome {
        for candidate in candidates {
            self.queue_unsolicited(candidate);
        }
        self.mark_correlation_deadline_expired();
        ProcessOutcome::CorrelationDeadlineExpired
    }

    fn workflow_response_limit_reached(&mut self, max_responses: usize) -> bool {
        if self.response_count < max_responses {
            return false;
        }
        self.diagnostics.push_once(Diagnostic::warning(
            "exchange.response_limit",
            format!(
                "matched response limit {max_responses} reached; later responses were not retained"
            ),
        ));
        true
    }

    fn queue_unsolicited(&mut self, candidate: UnsolicitedEvidence) {
        self.pending_events
            .push(super::contract::Event::Unsolicited {
                frame: candidate.decoded,
            });
    }

    fn mark_correlation_deadline_expired(&mut self) {
        self.correlation_deadline_expired = true;
        self.diagnostics.push_once(Diagnostic::warning(
            "exchange.correlation_deadline",
            "response correlation stopped at the bounded exchange deadline",
        ));
    }

    fn expire_decoded(
        &mut self,
        identity: RecordIdentity,
        decoded: DecodedPacket,
        options: &Options,
    ) -> ProcessOutcome {
        self.mark_correlation_deadline_expired();
        self.retain_unsolicited(identity, decoded, options, None);
        ProcessOutcome::CorrelationDeadlineExpired
    }
}

fn unsolicited_freshness(
    received_at: Option<Instant>,
    sent: &[std::sync::Arc<crate::SentPacket>],
    deadline: Instant,
) -> Option<UnsolicitedFreshness> {
    let received_at = received_at.filter(|received_at| *received_at <= deadline)?;
    let eligible_requests =
        sent.partition_point(|sent| sent.timing().freshness_marker().monotonic() <= received_at);
    (eligible_requests != 0).then_some(UnsolicitedFreshness {
        received_at,
        eligible_requests,
    })
}

#[cfg(test)]
mod tests;
