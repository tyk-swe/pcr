// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Instant;

use packetcraftr_core::{
    decode::DecodedPacket, diagnostic::Diagnostic, frame::Frame, matcher::Match, registry::Registry,
};
use packetcraftr_netio::{
    capture::{Captured, RecordIdentity},
    transmit::Timing,
};

use super::Response;
use super::accumulator::{
    Accumulator, DuplicateRecord, ProcessContext, ProcessOutcome, UnsolicitedEvidence,
    UnsolicitedFreshness, WorkflowResponseMatcher,
};
use super::{Collection, Window};

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

fn ensure_correlation_active(deadline: &Window) -> Result<(), CorrelationDeadlineExpired> {
    if deadline.expired() {
        return Err(CorrelationDeadlineExpired);
    }
    Ok(())
}

fn select_attribution(
    registry: &Registry,
    sent: &[std::sync::Arc<crate::evidence::SentPacket>],
    received_at: Option<Instant>,
    decoded: &DecodedPacket,
    deadline: &Window,
) -> Result<Attribution, CorrelationDeadlineExpired> {
    let mut best_match: Option<Match> = None;
    let mut equally_best = Vec::new();
    for (request_index, sent_request) in sent.iter().enumerate() {
        ensure_correlation_active(deadline)?;
        let Some(received_at) = received_at else {
            continue;
        };
        let timing = sent_request.timing();
        if received_at > deadline.ends_at() || !capture_follows_send(received_at, timing) {
            continue;
        }

        let mut request_match: Option<Match> = None;
        let request = &sent_request.built().packet;
        for layer in request.iter() {
            ensure_correlation_active(deadline)?;
            let Some(matcher) = registry.matcher(layer.protocol_id().as_str()) else {
                continue;
            };
            let candidate = matcher.matches(request, &decoded.packet);
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

/// The requests sent before the frame arrived that the workflow accepts it as a reply to.
fn workflow_attribution(
    sent: &[std::sync::Arc<crate::evidence::SentPacket>],
    freshness: UnsolicitedFreshness,
    decoded: &DecodedPacket,
    deadline: &Window,
    matches_request: &mut WorkflowResponseMatcher<'_>,
) -> Result<Attribution, CorrelationDeadlineExpired> {
    let mut winners = Vec::new();
    for (request_index, sent_request) in sent.iter().enumerate().take(freshness.eligible_requests) {
        let matched = matches_request(request_index, &sent_request.built().packet, decoded);
        ensure_correlation_active(deadline)?;
        if matched {
            winners.push(request_index);
        }
    }
    Ok(attribution(&winners))
}

impl Accumulator {
    /// A `matcher` lets a frame that a limit refused count as a refused reply.
    pub(crate) fn process(
        &mut self,
        captured: Captured,
        context: ProcessContext<'_>,
        matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<ProcessOutcome, DuplicateRecord> {
        let identity = captured.identity();
        if !self.can_retain_record(identity) {
            return Err(DuplicateRecord);
        }
        let Captured {
            frame, received_at, ..
        } = captured;
        if self.correlation_deadline_expired || context.window.expired() {
            return Ok(self.retain_capture_after_deadline(identity, frame, context));
        }

        let decoded = match self.decode_capture(identity, frame, context) {
            Ok(decoded) => decoded,
            Err(outcome) => return Ok(outcome),
        };
        Ok(self.correlate_decoded_capture(identity, received_at, decoded, context, matcher))
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
            .decode(frame, context.collection.decode.clone())
        {
            Ok(decoded) => {
                self.retain_unsolicited(identity, decoded, context.collection, None);
            }
            Err(_) => self.retain_undecoded(identity, raw_frame, context.collection),
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
            .decode(frame, context.collection.decode.clone())
        {
            Ok(decoded) => {
                if context.window.expired() {
                    return Err(self.expire_decoded(identity, decoded, context.collection));
                }
                Ok(decoded)
            }
            Err(error) => {
                if context.window.expired() {
                    self.mark_correlation_deadline_expired();
                    self.retain_undecoded(identity, raw_frame, context.collection);
                    return Err(ProcessOutcome::CorrelationDeadlineExpired);
                }
                self.diagnostics.push_once(Diagnostic::warning(
                    "exchange.decode_error",
                    format!(
                        "captured frame could not be decoded: {}",
                        packetcraftr_core::error::render(&error)
                    ),
                ));
                self.retain_undecoded(identity, raw_frame, context.collection);
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
        matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> ProcessOutcome {
        let integrity_failure = decoded
            .diagnostics
            .iter()
            .any(Diagnostic::is_checksum_failure);
        if context.window.expired() {
            return self.expire_decoded(identity, decoded, context.collection);
        }
        if integrity_failure {
            self.diagnostics.push_once(Diagnostic::warning(
                "exchange.integrity_rejected",
                "a response whose checksum did not verify was not correlated",
            ));
            self.retain_uncorrelated(identity, received_at, decoded, context, matcher);
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
            context.sent,
            received_at,
            &decoded,
            context.window,
        ) {
            Ok(attribution) => attribution,
            Err(CorrelationDeadlineExpired) => {
                return self.expire_decoded(identity, decoded, context.collection);
            }
        };
        self.record_attribution(
            identity,
            received_at,
            decoded,
            attribution,
            context,
            matcher,
        )
    }

    fn record_attribution(
        &mut self,
        identity: RecordIdentity,
        received_at: Option<Instant>,
        decoded: DecodedPacket,
        attribution: Attribution,
        context: ProcessContext<'_>,
        matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> ProcessOutcome {
        match attribution {
            Attribution::Ambiguous => {
                self.diagnostics.push_once(
                    Diagnostic::warning(
                        "exchange.ambiguous_attribution",
                        "a captured response matched several requests equally and was retained as unsolicited",
                    ),
                );
                self.retain_uncorrelated(identity, received_at, decoded, context, matcher);
            }
            Attribution::Unique(request_index) => {
                let received_at = received_at.expect("only timestamped capture frames can match");
                if context.window.expired() {
                    return self.expire_decoded(identity, decoded, context.collection);
                }
                if self.response_count >= context.collection.max_responses {
                    self.diagnostics.push_once(Diagnostic::warning(
                        "exchange.response_limit",
                        format!(
                            "matched response limit {} reached; later responses were not retained",
                            context.collection.max_responses
                        ),
                    ));
                    self.refuse_reply(request_index, "exchange.response_limit");
                    return ProcessOutcome::Continue;
                }
                match self.reserve_decoded_evidence(
                    decoded.frame.bytes().len(),
                    0,
                    context.collection,
                ) {
                    Ok(()) => {
                        self.mark_record_retained(identity);
                        // The attributed request was sent; counters stay under `max_responses`.
                        self.record_response(request_index);
                        self.pending_events.push(super::Event::Response(Response {
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
                    Err(limit) => self.refuse_reply(request_index, limit),
                }
            }
            Attribution::None => {
                if context.sent.len() < context.request_count {
                    self.diagnostics.push_once(
                        Diagnostic::info(
                            "exchange.pre_send_frame",
                            "a captured frame arrived before one or more requests were sent and was not correlated to those requests",
                        ),
                    );
                }
                self.retain_uncorrelated(identity, received_at, decoded, context, matcher);
            }
        }
        ProcessOutcome::Continue
    }

    /// A refused frame is a refused reply only when the workflow would have promoted it as the
    /// sole reply to a request; any other frame is not evidence about a request either way.
    fn retain_uncorrelated(
        &mut self,
        identity: RecordIdentity,
        received_at: Option<Instant>,
        decoded: DecodedPacket,
        context: ProcessContext<'_>,
        matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) {
        let freshness = unsolicited_freshness(received_at, context.sent, context.window.ends_at());
        let Some(refused) =
            self.retain_unsolicited(identity, decoded, context.collection, freshness)
        else {
            return;
        };
        let Some(matches_request) = matcher else {
            return;
        };
        if let Ok(Attribution::Unique(request_index)) = workflow_attribution(
            context.sent,
            refused.freshness,
            &refused.decoded,
            context.window,
            matches_request,
        ) {
            self.refuse_reply(request_index, refused.limit);
        }
    }

    pub(crate) fn promote_workflow_unsolicited(
        &mut self,
        context: ProcessContext<'_>,
        matches_request: &mut WorkflowResponseMatcher<'_>,
    ) -> ProcessOutcome {
        let ProcessContext {
            sent,
            window: deadline,
            collection,
            ..
        } = context;
        let max_responses = collection.max_responses;
        if self.unsolicited.is_empty() {
            return ProcessOutcome::Continue;
        }
        let mut candidates = std::mem::take(&mut self.unsolicited).into_iter();
        if deadline.expired() {
            return self.expire_workflow_candidates(candidates);
        }

        while let Some(candidate) = candidates.next() {
            if deadline.expired() {
                return self
                    .expire_workflow_candidates(std::iter::once(candidate).chain(candidates));
            }
            let Some(freshness) = candidate.freshness else {
                self.queue_unsolicited(candidate);
                continue;
            };
            let request_index = match workflow_attribution(
                sent,
                freshness,
                &candidate.decoded,
                deadline,
                matches_request,
            ) {
                Err(CorrelationDeadlineExpired) => {
                    return self
                        .expire_workflow_candidates(std::iter::once(candidate).chain(candidates));
                }
                Ok(Attribution::Unique(request_index)) => request_index,
                Ok(attribution) => {
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
            if self.workflow_response_limit_reached(max_responses) {
                self.refuse_reply(request_index, "exchange.response_limit");
                self.queue_unsolicited(candidate);
                continue;
            }
            // The counters were checked against `max_responses` before acceptance.
            self.record_response(request_index);
            self.retained_unmatched = self
                .retained_unmatched
                .checked_sub(1)
                .expect("workflow candidates are retained unmatched evidence");
            // `request_index` is below a partition point in `sent`, so it is in bounds.
            let sent_timing_monotonic = sent[request_index].timing().freshness_marker().monotonic();
            self.pending_events.push(super::Event::Response(Response {
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
        self.pending_events.push(super::Event::Unsolicited {
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
        collection: &Collection,
    ) -> ProcessOutcome {
        self.mark_correlation_deadline_expired();
        self.retain_unsolicited(identity, decoded, collection, None);
        ProcessOutcome::CorrelationDeadlineExpired
    }
}

fn unsolicited_freshness(
    received_at: Option<Instant>,
    sent: &[std::sync::Arc<crate::evidence::SentPacket>],
    ends_at: Instant,
) -> Option<UnsolicitedFreshness> {
    let received_at = received_at.filter(|received_at| *received_at <= ends_at)?;
    let eligible_requests =
        sent.partition_point(|sent| sent.timing().freshness_marker().monotonic() <= received_at);
    (eligible_requests != 0).then_some(UnsolicitedFreshness {
        received_at,
        eligible_requests,
    })
}

#[cfg(test)]
mod tests;
