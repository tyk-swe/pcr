// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Timestamped response correlation and workflow promotion.

use std::time::Instant;

use packetcraftr_network::capture::{Captured, RecordIdentity};
use packetcraftr_network::transmit::Timing as TransmissionTiming;
use packetcraftr_packet::{
    decode::Result as DecodedPacket,
    diagnostic::{Diagnostic, Severity as DiagnosticSeverity, push_diagnostic_once},
    matcher::Result as MatchResult,
};

use super::accumulator::{
    ExchangeAccumulator, ExchangeProcessContext, ExchangeProcessOutcome, UnsolicitedFreshness,
    WorkflowPromotionContext, WorkflowResponseMatcher,
};
use super::contract::{ExchangeOptions, MatchedResponse};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attribution {
    None,
    Unique(usize),
    Ambiguous,
}

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

        let mut matched: Option<(usize, MatchResult)> = None;
        let mut equally_best = Vec::new();
        for (request_index, prepared_request) in prepared.iter().take(sent.len()).enumerate() {
            if Instant::now() >= deadline {
                return self.expire_decoded(identity, decoded, options);
            }
            let Some(received_at) = received_at else {
                continue;
            };
            let timing = sent[request_index].timing();
            if received_at > deadline {
                continue;
            }
            if !capture_follows_send(received_at, timing) {
                continue;
            }
            let mut result = None;
            for layer in prepared_request.built.packet.iter() {
                if Instant::now() >= deadline {
                    return self.expire_decoded(identity, decoded, options);
                }
                let Some(matcher) = registry.matcher(layer.protocol_id().as_str()) else {
                    continue;
                };
                let candidate = matcher.matches(&prepared_request.built.packet, &decoded.packet);
                if Instant::now() >= deadline {
                    return self.expire_decoded(identity, decoded, options);
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
                return self.expire_decoded(identity, decoded, options);
            }
            let Some(result) = result else {
                continue;
            };
            let replace = matched
                .as_ref()
                .is_none_or(|(_, best)| result.confidence > best.confidence);
            if replace {
                equally_best.clear();
                equally_best.push(request_index);
                matched = Some((request_index, result));
            } else if matched
                .as_ref()
                .is_some_and(|(_, best)| result.confidence == best.confidence)
            {
                equally_best.push(request_index);
            }
        }
        if Instant::now() >= deadline {
            return self.expire_decoded(identity, decoded, options);
        }

        if attribution(&equally_best) == Attribution::Ambiguous {
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
        } else if let Some((request_index, _)) = matched {
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
        } else {
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
        debug_assert_eq!(self.unsolicited.len(), self.unsolicited_freshness.len());
        if self.workflow_examined_unsolicited >= self.unsolicited.len() {
            return ExchangeProcessOutcome::Continue;
        }
        if Instant::now() >= deadline {
            self.unsolicited_freshness.fill(None);
            self.workflow_examined_unsolicited = self.unsolicited.len();
            self.mark_correlation_deadline_expired();
            return ExchangeProcessOutcome::CorrelationDeadlineExpired;
        }
        if self.workflow_response_limit_reached(max_responses) {
            self.workflow_examined_unsolicited = self.unsolicited.len();
            return ExchangeProcessOutcome::Continue;
        }

        let mut candidates = self
            .unsolicited
            .split_off(self.workflow_examined_unsolicited)
            .into_iter()
            .zip(
                self.unsolicited_freshness
                    .split_off(self.workflow_examined_unsolicited),
            );
        while let Some((decoded, freshness)) = candidates.next() {
            if Instant::now() >= deadline {
                self.unsolicited.push(decoded);
                self.unsolicited_freshness.push(None);
                for (decoded, _) in candidates {
                    self.unsolicited.push(decoded);
                    self.unsolicited_freshness.push(None);
                }
                self.unsolicited_freshness.fill(None);
                self.workflow_examined_unsolicited = self.unsolicited.len();
                self.mark_correlation_deadline_expired();
                return ExchangeProcessOutcome::CorrelationDeadlineExpired;
            }
            let Some(freshness) = freshness else {
                self.unsolicited.push(decoded);
                self.unsolicited_freshness.push(None);
                continue;
            };
            if self.workflow_response_limit_reached(max_responses) {
                self.unsolicited.push(decoded);
                self.unsolicited_freshness.push(Some(freshness));
                continue;
            }
            let mut winners = Vec::new();
            for (request_index, prepared_request) in prepared
                .iter()
                .enumerate()
                .take(freshness.eligible_requests)
            {
                let matched =
                    matches_request(request_index, &prepared_request.built.packet, &decoded);
                if Instant::now() >= deadline {
                    self.unsolicited.push(decoded);
                    self.unsolicited_freshness.push(None);
                    for (decoded, _) in candidates {
                        self.unsolicited.push(decoded);
                        self.unsolicited_freshness.push(None);
                    }
                    self.unsolicited_freshness.fill(None);
                    self.workflow_examined_unsolicited = self.unsolicited.len();
                    self.mark_correlation_deadline_expired();
                    return ExchangeProcessOutcome::CorrelationDeadlineExpired;
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
                    self.unsolicited.push(decoded);
                    self.unsolicited_freshness.push(Some(freshness));
                    continue;
                }
            };
            self.response_counts[request_index] += 1;
            self.responses.push(MatchedResponse {
                request_index,
                response: decoded,
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
mod tests {
    use bytes::Bytes;
    use packetcraftr_network::capture::Captured;
    use packetcraftr_network::transmit::Submission;
    use packetcraftr_packet::frame::{Frame, LinkType};
    use packetcraftr_packet::{Packet, layer::Raw};
    use packetcraftr_packet::{decode::Decoder, protocol::builtin::registry as default_registry};
    use std::{sync::Arc, time::Duration};

    use super::*;

    fn raw_packet() -> Packet {
        let mut packet = Packet::new();
        packet.push(Raw::new(Bytes::from_static(&[0])));
        packet
    }

    #[test]
    fn unsolicited_freshness_requires_proven_ingress_after_at_least_one_send() {
        let sent = [
            crate::evidence::test_sent_packet(raw_packet()),
            crate::evidence::test_sent_packet(raw_packet()),
            crate::evidence::test_sent_packet(raw_packet()),
        ];
        let first_marker = sent[0].timing().freshness_marker().monotonic();
        let second_marker = sent[1].timing().freshness_marker().monotonic();
        let final_marker = sent[2].timing().freshness_marker().monotonic();
        let deadline = final_marker + Duration::from_millis(10);

        assert!(unsolicited_freshness(None, &sent, deadline).is_none());
        assert!(
            unsolicited_freshness(
                Some(
                    first_marker
                        .checked_sub(Duration::from_nanos(1))
                        .expect("marker")
                ),
                &sent,
                deadline,
            )
            .is_none()
        );
        assert!(
            unsolicited_freshness(Some(deadline + Duration::from_nanos(1)), &sent, deadline)
                .is_none()
        );

        let first = unsolicited_freshness(Some(first_marker), &sent, deadline)
            .expect("first request is eligible at its send marker");
        assert_eq!(first.received_at, first_marker);
        assert_eq!(first.eligible_requests, 1);

        let between = unsolicited_freshness(Some(second_marker), &sent, deadline)
            .expect("two requests are eligible at the second completion marker");
        assert_eq!(between.eligible_requests, 2);

        let final_frame = unsolicited_freshness(Some(deadline), &sent, deadline)
            .expect("all requests remain eligible through the deadline");
        assert_eq!(final_frame.eligible_requests, 3);
    }

    #[test]
    fn capture_inside_submission_interval_is_not_proven_fresh() {
        let submission = Submission::start();
        let inside = submission.started().monotonic();
        std::thread::yield_now();
        let sent = [crate::evidence::test_sent_packet_with_report(
            raw_packet(),
            submission.complete(1, Bytes::from_static(&[0])),
        )];
        let deadline = sent[0].timing().freshness_marker().monotonic() + Duration::from_secs(1);

        assert!(unsolicited_freshness(Some(inside), &sent, deadline).is_none());
    }

    #[test]
    fn duplicated_ingress_record_cannot_enter_several_evidence_categories() {
        let captured = Captured::new(
            Frame::without_timestamp(LinkType::RAW, Bytes::from_static(&[0x45]))
                .expect("fixture frame"),
            Instant::now(),
        );
        let registry = Arc::new(default_registry().expect("built-in registry"));
        let dissector = Decoder::new(Arc::clone(&registry));
        let options = ExchangeOptions::default();
        let mut accumulator = ExchangeAccumulator::new(0);
        let context = ExchangeProcessContext {
            registry: &registry,
            dissector: &dissector,
            prepared: &[],
            sent: &[],
            deadline: Instant::now() + Duration::from_secs(1),
            options: &options,
        };

        assert_eq!(
            accumulator.process(captured.clone(), context),
            ExchangeProcessOutcome::Continue
        );
        assert_eq!(
            accumulator.process(captured, context),
            ExchangeProcessOutcome::DuplicateRecordIdentity
        );
        assert_eq!(
            accumulator.responses.len()
                + accumulator.unsolicited.len()
                + accumulator.undecoded.len(),
            1
        );
    }

    #[test]
    fn duplicate_tracking_is_bounded_to_retained_evidence() {
        let retained = Captured::new(
            Frame::without_timestamp(LinkType::RAW, Bytes::from_static(&[0x45]))
                .expect("fixture frame"),
            Instant::now(),
        );
        let dropped = Captured::new(
            Frame::without_timestamp(LinkType::RAW, Bytes::from_static(&[0x45]))
                .expect("fixture frame"),
            Instant::now(),
        );
        let registry = Arc::new(default_registry().expect("built-in registry"));
        let dissector = Decoder::new(Arc::clone(&registry));
        let options = ExchangeOptions {
            max_unsolicited: 1,
            ..ExchangeOptions::default()
        };
        let mut accumulator = ExchangeAccumulator::new(0);
        let context = ExchangeProcessContext {
            registry: &registry,
            dissector: &dissector,
            prepared: &[],
            sent: &[],
            deadline: Instant::now() + Duration::from_secs(1),
            options: &options,
        };

        assert_eq!(
            accumulator.process(retained, context),
            ExchangeProcessOutcome::Continue
        );
        assert_eq!(
            accumulator.process(dropped.clone(), context),
            ExchangeProcessOutcome::Continue
        );
        assert_eq!(
            accumulator.process(dropped, context),
            ExchangeProcessOutcome::Continue
        );
        assert_eq!(accumulator.retained_record_identities.len(), 1);
        assert_eq!(
            accumulator.unsolicited.len() + accumulator.undecoded.len(),
            1
        );
    }

    #[test]
    fn identical_probe_matches_are_ambiguous_not_uniquely_attributed() {
        assert_eq!(attribution(&[2, 7]), Attribution::Ambiguous);
        assert_eq!(attribution(&[2]), Attribution::Unique(2));
    }

    #[test]
    fn monotonic_ingress_proves_freshness_despite_wall_clock_skew() {
        let report = Submission::start().complete(0, Bytes::new());
        let marker = report.timing().freshness_marker();
        let received_at = marker.monotonic() + Duration::from_millis(1);
        let _captured_wall = marker
            .wall_clock()
            .checked_sub(Duration::from_millis(1))
            .expect("marker permits subtraction");

        assert!(capture_follows_send(received_at, report.timing()));
    }

    #[test]
    fn pre_send_capture_cannot_be_freshened_by_a_claimed_small_latency() {
        let report = Submission::start().complete(0, Bytes::new());
        let marker = report.timing().freshness_marker();
        let pre_send = marker
            .monotonic()
            .checked_sub(Duration::from_nanos(1))
            .expect("marker permits subtraction");
        let _untrusted_claim = Duration::from_millis(1);

        assert!(!capture_follows_send(pre_send, report.timing()));
    }
}
