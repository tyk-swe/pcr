// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Timestamped response correlation and workflow promotion.

use std::time::Instant;

use packetcraftr_network::capture::Captured;
use packetcraftr_packet::{
    decode::Result as DecodedPacket,
    diagnostic::{Diagnostic, Severity as DiagnosticSeverity, push_diagnostic_once},
    matcher::Result as MatchResult,
};

use super::accumulator::{
    ExchangeAccumulator, ExchangeProcessContext, ExchangeProcessOutcome, WorkflowPromotionContext,
    WorkflowResponseMatcher,
};
use super::contract::{ExchangeOptions, MatchedResponse};

impl ExchangeAccumulator {
    pub(crate) fn process(
        &mut self,
        captured: Captured,
        context: ExchangeProcessContext<'_>,
    ) -> ExchangeProcessOutcome {
        let ExchangeProcessContext {
            registry,
            dissector,
            prepared,
            sent,
            deadline,
            options,
        } = context;
        let record_id = captured.id();
        let Captured {
            frame, received_at, ..
        } = captured;
        if self.correlation_deadline_expired || Instant::now() >= deadline {
            self.mark_correlation_deadline_expired();
            let raw_frame = frame.clone();
            match dissector.decode(frame, options.decode.clone()) {
                Ok(decoded) => {
                    self.retain_unsolicited(decoded, record_id, received_at, options, false)
                }
                Err(_) => self.retain_undecoded(raw_frame, record_id, received_at, options),
            }
            return ExchangeProcessOutcome::CorrelationDeadlineExpired;
        }
        let raw_frame = frame.clone();
        let decoded = match dissector.decode(frame, options.decode.clone()) {
            Ok(decoded) => {
                if Instant::now() >= deadline {
                    return self.expire_decoded(decoded, record_id, received_at, options);
                }
                decoded
            }
            Err(error) => {
                if Instant::now() >= deadline {
                    self.mark_correlation_deadline_expired();
                    self.retain_undecoded(raw_frame, record_id, received_at, options);
                    return ExchangeProcessOutcome::CorrelationDeadlineExpired;
                }
                push_diagnostic_once(
                    &mut self.diagnostics,
                    Diagnostic::warning(
                        "exchange.decode_error",
                        format!("captured frame could not be decoded: {error}"),
                    ),
                );
                self.retain_undecoded(raw_frame, record_id, received_at, options);
                return ExchangeProcessOutcome::Continue;
            }
        };
        let integrity_failure = decoded.diagnostics.iter().any(|diagnostic| {
            diagnostic.code.contains("checksum") && diagnostic.severity != DiagnosticSeverity::Info
        });
        if Instant::now() >= deadline {
            return self.expire_decoded(decoded, record_id, received_at, options);
        }
        if integrity_failure {
            push_diagnostic_once(
                &mut self.diagnostics,
                Diagnostic::warning(
                    "exchange.integrity_rejected",
                    "a response with failed checksum validation was not correlated",
                ),
            );
            self.retain_unsolicited(decoded, record_id, received_at, options, true);
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

        let mut candidates = Vec::new();
        for (request_index, prepared_request) in prepared.iter().take(sent.len()).enumerate() {
            if Instant::now() >= deadline {
                return self.expire_decoded(decoded, record_id, received_at, options);
            }
            let Some(received_at) = received_at else {
                continue;
            };
            if received_at < sent[request_index].freshness_at()
                || received_at > deadline
                || !wall_clock_is_consistent(&sent[request_index], &decoded)
            {
                continue;
            }
            let mut result = None;
            for layer in prepared_request.built.packet.iter() {
                if Instant::now() >= deadline {
                    return self.expire_decoded(decoded, record_id, Some(received_at), options);
                }
                let Some(matcher) = registry.matcher(layer.protocol_id().as_str()) else {
                    continue;
                };
                let candidate = matcher.matches(&prepared_request.built.packet, &decoded.packet);
                if Instant::now() >= deadline {
                    return self.expire_decoded(decoded, record_id, Some(received_at), options);
                }
                if candidate.matched
                    && result
                        .as_ref()
                        .is_none_or(|best: &MatchResult| candidate.confidence > best.confidence)
                {
                    result = Some(candidate);
                }
            }
            if Instant::now() >= deadline {
                return self.expire_decoded(decoded, record_id, Some(received_at), options);
            }
            let Some(result) = result else {
                continue;
            };
            candidates.push((request_index, result));
        }
        if Instant::now() >= deadline {
            return self.expire_decoded(decoded, record_id, received_at, options);
        }

        let Some(best_confidence) = candidates.iter().map(|(_, result)| result.confidence).max()
        else {
            if sent.len() < prepared.len() {
                push_diagnostic_once(
                    &mut self.diagnostics,
                    Diagnostic::info(
                        "exchange.pre_send_frame",
                        "a captured frame arrived before one or more requests were sent and was not correlated to those requests",
                    ),
                );
            }
            self.retain_unsolicited(decoded, record_id, received_at, options, true);
            return ExchangeProcessOutcome::Continue;
        };
        let best: Vec<_> = candidates
            .into_iter()
            .filter(|(_, result)| result.confidence == best_confidence)
            .collect();
        if best.len() != 1 {
            push_diagnostic_once(
                &mut self.diagnostics,
                Diagnostic::warning(
                    "exchange.ambiguous_capture",
                    "a captured response matched multiple requests with equal confidence; it was retained without request attribution",
                ),
            );
            self.retain_unsolicited(decoded, record_id, received_at, options, false);
            return ExchangeProcessOutcome::Continue;
        }
        let request_index = best[0].0;
        {
            let received_at = received_at.expect("only timestamped capture frames can match");
            if Instant::now() >= deadline {
                return self.expire_decoded(decoded, record_id, Some(received_at), options);
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
                return self.expire_decoded(decoded, record_id, Some(received_at), options);
            }
            if self.reserve_decoded_evidence(decoded.original.len(), options) {
                self.response_counts[request_index] += 1;
                self.responses.push(MatchedResponse::new(
                    record_id,
                    request_index,
                    decoded,
                    received_at,
                    received_at.saturating_duration_since(sent[request_index].freshness_at()),
                ));
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
            self.workflow_examined_unsolicited = self.unsolicited.len();
            self.mark_correlation_deadline_expired();
            return ExchangeProcessOutcome::CorrelationDeadlineExpired;
        }
        if self.workflow_response_limit_reached(max_responses) {
            self.workflow_examined_unsolicited = self.unsolicited.len();
            return ExchangeProcessOutcome::Continue;
        }

        let pending = self
            .unsolicited
            .split_off(self.workflow_examined_unsolicited);
        for mut decoded in pending {
            if Instant::now() >= deadline {
                self.unsolicited.push(decoded);
                self.workflow_examined_unsolicited = self.unsolicited.len();
                self.mark_correlation_deadline_expired();
                return ExchangeProcessOutcome::CorrelationDeadlineExpired;
            }
            if !decoded.workflow_eligible {
                self.unsolicited.push(decoded);
                continue;
            }
            let Some(received_at) = decoded.received_at else {
                decoded.workflow_eligible = false;
                self.unsolicited.push(decoded);
                continue;
            };
            let eligible_requests = sent.partition_point(|send| send.freshness_at() <= received_at);
            if eligible_requests == 0 || received_at > deadline {
                self.unsolicited.push(decoded);
                continue;
            }
            if self.workflow_response_limit_reached(max_responses) {
                self.unsolicited.push(decoded);
                continue;
            }
            let mut winners = Vec::new();
            for (request_index, prepared_request) in
                prepared.iter().enumerate().take(eligible_requests)
            {
                let matched =
                    matches_request(
                        request_index,
                        &prepared_request.built.packet,
                        &decoded.response,
                    ) && wall_clock_is_consistent(&sent[request_index], &decoded.response);
                if Instant::now() >= deadline {
                    self.unsolicited.push(decoded);
                    self.workflow_examined_unsolicited = self.unsolicited.len();
                    self.mark_correlation_deadline_expired();
                    return ExchangeProcessOutcome::CorrelationDeadlineExpired;
                }
                if matched {
                    winners.push(request_index);
                }
            }
            if winners.len() != 1 {
                if winners.len() > 1 {
                    push_diagnostic_once(
                        &mut self.diagnostics,
                        Diagnostic::warning(
                            "exchange.ambiguous_capture",
                            "an unsolicited response matched multiple identical requests; it remained unattribtued",
                        ),
                    );
                    decoded.workflow_eligible = false;
                }
                self.unsolicited.push(decoded);
                continue;
            }
            let request_index = winners[0];
            self.response_counts[request_index] += 1;
            self.responses.push(MatchedResponse::new(
                decoded.record_id,
                request_index,
                decoded.response,
                received_at,
                received_at.saturating_duration_since(sent[request_index].freshness_at()),
            ));
        }
        self.workflow_examined_unsolicited = self.unsolicited.len();
        // Ambient frames remain available from Client::exchange, but the
        // stable workflow execution types cannot carry per-request monotonic
        // eligibility. Do not reintroduce an unsafe wall-clock fallback.
        ExchangeProcessOutcome::Continue
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
        decoded: DecodedPacket,
        record_id: packetcraftr_network::capture::CaptureRecordId,
        received_at: Option<Instant>,
        options: &ExchangeOptions,
    ) -> ExchangeProcessOutcome {
        self.mark_correlation_deadline_expired();
        self.retain_unsolicited(decoded, record_id, received_at, options, false);
        ExchangeProcessOutcome::CorrelationDeadlineExpired
    }
}

fn wall_clock_is_consistent(sent: &crate::send::SentPacket, decoded: &DecodedPacket) -> bool {
    match (sent.timing().output_wall_clock(), decoded.frame.timestamp) {
        (Some(sent_at), Some(received_at)) => received_at >= sent_at,
        _ => true,
    }
}
