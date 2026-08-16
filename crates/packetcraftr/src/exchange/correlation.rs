// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Timestamped response correlation and workflow promotion.

use std::time::Instant;

use packetcraftr_core::{
    decode::DecodedPacket,
    diagnostic::{Diagnostic, DiagnosticSeverity, push_diagnostic_once},
    matcher::MatchResult,
    registry::Registry,
};
use packetcraftr_netio::capture::{Captured, RecordIdentity};
use packetcraftr_netio::transmit::Timing as TransmissionTiming;

use super::accumulator::{
    ExchangeAccumulator, ExchangeProcessContext, ExchangeProcessOutcome, UnsolicitedEvidence,
    UnsolicitedFreshness, WorkflowPromotionContext, WorkflowResponseMatcher,
};
use super::contract::{ExchangeOptions, MatchedResponse};
use super::preparation::PreparedExchangePacket;

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

fn capture_follows_send(received_at: Instant, timing: TransmissionTiming) -> bool {
    received_at >= timing.freshness_marker().monotonic()
}

fn ensure_correlation_active(deadline: Instant) -> Result<(), CorrelationDeadlineExpired> {
    if Instant::now() >= deadline {
        return Err(CorrelationDeadlineExpired);
    }
    Ok(())
}

fn select_attribution(
    registry: &Registry,
    prepared: &[PreparedExchangePacket],
    sent: &[crate::SentPacket],
    received_at: Option<Instant>,
    decoded: &DecodedPacket,
    deadline: Instant,
) -> Result<Attribution, CorrelationDeadlineExpired> {
    let mut best_match: Option<MatchResult> = None;
    let mut equally_best = Vec::new();
    for (request_index, prepared_request) in prepared.iter().take(sent.len()).enumerate() {
        ensure_correlation_active(deadline)?;
        let Some(received_at) = received_at else {
            continue;
        };
        let timing = sent[request_index].timing();
        if received_at > deadline || !capture_follows_send(received_at, timing) {
            continue;
        }

        let mut request_match = None;
        for layer in prepared_request.built.packet.iter() {
            ensure_correlation_active(deadline)?;
            let Some(matcher) = registry.matcher(layer.protocol_id().as_str()) else {
                continue;
            };
            let candidate = matcher.matches(&prepared_request.built.packet, &decoded.packet);
            ensure_correlation_active(deadline)?;
            if candidate.matched
                && request_match
                    .as_ref()
                    .is_none_or(|best: &MatchResult| candidate.confidence > best.confidence)
            {
                request_match = Some(candidate);
            }
        }
        ensure_correlation_active(deadline)?;
        let Some(request_match) = request_match else {
            continue;
        };

        let replace = best_match
            .as_ref()
            .is_none_or(|best| request_match.confidence > best.confidence);
        if replace {
            equally_best.clear();
            equally_best.push(request_index);
            best_match = Some(request_match);
        } else if best_match
            .as_ref()
            .is_some_and(|best| request_match.confidence == best.confidence)
        {
            equally_best.push(request_index);
        }
    }
    ensure_correlation_active(deadline)?;
    Ok(attribution(&equally_best))
}

impl ExchangeAccumulator {
    pub(crate) fn process(
        &mut self,
        captured: Captured,
        context: ExchangeProcessContext<'_>,
    ) -> ExchangeProcessOutcome {
        let identity = captured.identity();
        if !self.can_retain_record(identity) {
            return ExchangeProcessOutcome::DuplicateRecordIdentity;
        }
        let ExchangeProcessContext {
            registry,
            dissector,
            prepared,
            sent,
            deadline,
            options,
        } = context;
        let Captured {
            frame, received_at, ..
        } = captured;
        if self.correlation_deadline_expired || Instant::now() >= deadline {
            self.mark_correlation_deadline_expired();
            let raw_frame = frame.clone();
            match dissector.decode(frame, options.decode.clone()) {
                Ok(decoded) => self.retain_unsolicited(identity, decoded, options, None),
                Err(_) => self.retain_undecoded(identity, raw_frame, options),
            }
            return ExchangeProcessOutcome::CorrelationDeadlineExpired;
        }
        let raw_frame = frame.clone();
        let decoded = match dissector.decode(frame, options.decode.clone()) {
            Ok(decoded) => {
                if Instant::now() >= deadline {
                    return self.expire_decoded(identity, decoded, options);
                }
                decoded
            }
            Err(error) => {
                if Instant::now() >= deadline {
                    self.mark_correlation_deadline_expired();
                    self.retain_undecoded(identity, raw_frame, options);
                    return ExchangeProcessOutcome::CorrelationDeadlineExpired;
                }
                push_diagnostic_once(
                    &mut self.diagnostics,
                    Diagnostic::warning(
                        "exchange.decode_error",
                        format!("captured frame could not be decoded: {error}"),
                    ),
                );
                self.retain_undecoded(identity, raw_frame, options);
                return ExchangeProcessOutcome::Continue;
            }
        };
        let integrity_failure = decoded.diagnostics.iter().any(|diagnostic| {
            diagnostic.code.contains("checksum") && diagnostic.severity != DiagnosticSeverity::Info
        });
        if Instant::now() >= deadline {
            return self.expire_decoded(identity, decoded, options);
        }
        if integrity_failure {
            push_diagnostic_once(
                &mut self.diagnostics,
                Diagnostic::warning(
                    "exchange.integrity_rejected",
                    "a response with failed checksum validation was not correlated",
                ),
            );
            self.retain_unsolicited(
                identity,
                decoded,
                options,
                unsolicited_freshness(received_at, sent, deadline),
            );
            return ExchangeProcessOutcome::Continue;
        }

        if received_at.is_none() {
            push_diagnostic_once(
                &mut self.diagnostics,
                Diagnostic::warning(
                    "capture.ingress_time_unavailable",
                    "a capture provider returned a frame without an ingress marker; the frame was retained but not correlated",
                ),
            );
        }

        let attribution =
            match select_attribution(registry, prepared, sent, received_at, &decoded, deadline) {
                Ok(attribution) => attribution,
                Err(CorrelationDeadlineExpired) => {
                    return self.expire_decoded(identity, decoded, options);
                }
            };

        match attribution {
            Attribution::Ambiguous => {
                push_diagnostic_once(
                    &mut self.diagnostics,
                    Diagnostic::warning(
                        "exchange.ambiguous_attribution",
                        "a captured response matched several requests equally and was retained as unsolicited",
                    ),
                );
                self.retain_unsolicited(
                    identity,
                    decoded,
                    options,
                    unsolicited_freshness(received_at, sent, deadline),
                );
            }
            Attribution::Unique(request_index) => {
                let received_at = received_at.expect("only timestamped capture frames can match");
                if Instant::now() >= deadline {
                    return self.expire_decoded(identity, decoded, options);
                }
                if self.responses.len() >= options.max_responses {
                    push_diagnostic_once(
                        &mut self.diagnostics,
                        Diagnostic::warning(
                            "exchange.response_limit",
                            format!(
                                "matched response limit {} reached; later responses were not retained",
                                options.max_responses
                            ),
                        ),
                    );
                    return ExchangeProcessOutcome::Continue;
                }
                if Instant::now() >= deadline {
                    return self.expire_decoded(identity, decoded, options);
                }
                if self.reserve_decoded_evidence(decoded.original.len(), options) {
                    self.mark_record_retained(identity);
                    self.response_counts[request_index] += 1;
                    self.responses.push(MatchedResponse {
                        request_index,
                        response: decoded,
                        latency: received_at.duration_since(
                            sent[request_index].timing().freshness_marker().monotonic(),
                        ),
                    });
                }
            }
            Attribution::None => {
                if sent.len() < prepared.len() {
                    push_diagnostic_once(
                        &mut self.diagnostics,
                        Diagnostic::info(
                            "exchange.pre_send_frame",
                            "a captured frame arrived before one or more requests were sent and was not correlated to those requests",
                        ),
                    );
                }
                self.retain_unsolicited(
                    identity,
                    decoded,
                    options,
                    unsolicited_freshness(received_at, sent, deadline),
                );
            }
        }
        ExchangeProcessOutcome::Continue
    }

    pub(crate) fn promote_workflow_unsolicited(
        &mut self,
        context: WorkflowPromotionContext<'_>,
        matches_request: &mut WorkflowResponseMatcher<'_>,
    ) -> ExchangeProcessOutcome {
        let WorkflowPromotionContext {
            prepared,
            sent,
            deadline,
            max_responses,
        } = context;
        if self.workflow_examined_unsolicited >= self.unsolicited.len() {
            return ExchangeProcessOutcome::Continue;
        }
        if Instant::now() >= deadline {
            return self.expire_workflow_candidates(std::iter::empty());
        }
        if self.workflow_response_limit_reached(max_responses) {
            self.workflow_examined_unsolicited = self.unsolicited.len();
            return ExchangeProcessOutcome::Continue;
        }

        let mut candidates = self
            .unsolicited
            .split_off(self.workflow_examined_unsolicited)
            .into_iter();
        while let Some(candidate) = candidates.next() {
            if Instant::now() >= deadline {
                return self
                    .expire_workflow_candidates(std::iter::once(candidate).chain(candidates));
            }
            let Some(freshness) = candidate.freshness else {
                self.unsolicited.push(candidate);
                continue;
            };
            if self.workflow_response_limit_reached(max_responses) {
                self.unsolicited.push(candidate);
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
                if Instant::now() >= deadline {
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
                        push_diagnostic_once(
                            &mut self.diagnostics,
                            Diagnostic::warning(
                                "exchange.ambiguous_attribution",
                                "a workflow response matched several requests and was retained as unsolicited",
                            ),
                        );
                    }
                    self.unsolicited.push(candidate);
                    continue;
                }
            };
            self.response_counts[request_index] += 1;
            self.responses.push(MatchedResponse {
                request_index,
                response: candidate.decoded,
                latency: freshness
                    .received_at
                    .duration_since(sent[request_index].timing().freshness_marker().monotonic()),
            });
        }
        self.workflow_examined_unsolicited = self.unsolicited.len();
        // Ambient frames remain available from Client::exchange, but the
        // stable workflow execution types cannot carry per-request monotonic
        // eligibility. Do not reintroduce an unsafe wall-clock fallback.
        ExchangeProcessOutcome::Continue
    }

    fn expire_workflow_candidates(
        &mut self,
        candidates: impl IntoIterator<Item = UnsolicitedEvidence>,
    ) -> ExchangeProcessOutcome {
        self.unsolicited
            .extend(candidates.into_iter().map(|mut candidate| {
                candidate.freshness = None;
                candidate
            }));
        for evidence in &mut self.unsolicited {
            evidence.freshness = None;
        }
        self.workflow_examined_unsolicited = self.unsolicited.len();
        self.mark_correlation_deadline_expired();
        ExchangeProcessOutcome::CorrelationDeadlineExpired
    }

    fn workflow_response_limit_reached(&mut self, max_responses: usize) -> bool {
        if self.responses.len() < max_responses {
            return false;
        }
        push_diagnostic_once(
            &mut self.diagnostics,
            Diagnostic::warning(
                "exchange.response_limit",
                format!(
                    "matched response limit {max_responses} reached; later responses were not retained"
                ),
            ),
        );
        true
    }

    fn mark_correlation_deadline_expired(&mut self) {
        self.correlation_deadline_expired = true;
        push_diagnostic_once(
            &mut self.diagnostics,
            Diagnostic::warning(
                "exchange.correlation_deadline",
                "response correlation stopped at the bounded exchange deadline",
            ),
        );
    }

    fn expire_decoded(
        &mut self,
        identity: RecordIdentity,
        decoded: DecodedPacket,
        options: &ExchangeOptions,
    ) -> ExchangeProcessOutcome {
        self.mark_correlation_deadline_expired();
        self.retain_unsolicited(identity, decoded, options, None);
        ExchangeProcessOutcome::CorrelationDeadlineExpired
    }
}

fn unsolicited_freshness(
    received_at: Option<Instant>,
    sent: &[crate::SentPacket],
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
