// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Response matching, evidence retention, and workflow promotion state.

use std::time::Instant;

use packetcraftr_core::frame::Frame;
use packetcraftr_net::capture::CapturedFrame;
use packetcraftr_packet::{
    Packet,
    build::BuiltPacket,
    decode::{DecodedPacket, Dissector},
    diagnostic::push_diagnostic_once,
    registry::ProtocolRegistry,
};

use super::super::Stats;
use super::super::evidence::reserve_capture_evidence;
use super::contract::{ExchangeOptions, ExchangeResult, MatchedResponse};
use super::transaction::PreparedExchangePacket;

#[derive(Clone, Copy)]
struct UnsolicitedFreshness {
    received_at: Instant,
    eligible_requests: usize,
}

pub(crate) type WorkflowResponseMatcher<'a> =
    dyn FnMut(usize, &Packet, &DecodedPacket) -> bool + 'a;

pub(crate) struct ExchangeAccumulator {
    pub(crate) responses: Vec<MatchedResponse>,
    pub(crate) unsolicited: Vec<DecodedPacket>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<packetcraftr_packet::diagnostic::Diagnostic>,
    unsolicited_freshness: Vec<Option<UnsolicitedFreshness>>,
    retained_frames: usize,
    retained_bytes: usize,
    pub(crate) response_counts: Vec<usize>,
    correlation_deadline_expired: bool,
    workflow_examined_unsolicited: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct ExchangeProcessContext<'a> {
    pub(crate) registry: &'a ProtocolRegistry,
    pub(crate) dissector: &'a Dissector,
    pub(crate) prepared: &'a [PreparedExchangePacket],
    pub(crate) sent_at: &'a [Instant],
    pub(crate) deadline: Instant,
    pub(crate) options: &'a ExchangeOptions,
}

#[derive(Clone, Copy)]
pub(crate) struct WorkflowPromotionContext<'a> {
    pub(crate) prepared: &'a [PreparedExchangePacket],
    pub(crate) sent_at: &'a [Instant],
    pub(crate) deadline: Instant,
    pub(crate) max_responses: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExchangeProcessOutcome {
    Continue,
    CorrelationDeadlineExpired,
}

impl ExchangeAccumulator {
    pub(crate) fn new(requests: usize) -> Self {
        Self {
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            unsolicited_freshness: Vec::new(),
            retained_frames: 0,
            retained_bytes: 0,
            response_counts: vec![0; requests],
            correlation_deadline_expired: false,
            workflow_examined_unsolicited: 0,
        }
    }

    pub(crate) fn process(
        &mut self,
        captured: CapturedFrame,
        context: ExchangeProcessContext<'_>,
    ) -> ExchangeProcessOutcome {
        let ExchangeProcessContext {
            registry,
            dissector,
            prepared,
            sent_at,
            deadline,
            options,
        } = context;
        let CapturedFrame { frame, received_at } = captured;
        if self.correlation_deadline_expired || Instant::now() >= deadline {
            self.mark_correlation_deadline_expired();
            let raw_frame = frame.clone();
            match dissector.decode(frame, options.decode.clone()) {
                Ok(decoded) => self.retain_unsolicited(decoded, options, None),
                Err(_) => self.retain_undecoded(raw_frame, options),
            }
            return ExchangeProcessOutcome::CorrelationDeadlineExpired;
        }
        let raw_frame = frame.clone();
        let decoded = match dissector.decode(frame, options.decode.clone()) {
            Ok(decoded) => {
                if Instant::now() >= deadline {
                    return self.expire_decoded(decoded, options);
                }
                decoded
            }
            Err(error) => {
                if Instant::now() >= deadline {
                    self.mark_correlation_deadline_expired();
                    self.retain_undecoded(raw_frame, options);
                    return ExchangeProcessOutcome::CorrelationDeadlineExpired;
                }
                push_diagnostic_once(
                    &mut self.diagnostics,
                    packetcraftr_packet::diagnostic::Diagnostic::warning(
                        "exchange.decode_error",
                        format!("captured frame could not be decoded: {error}"),
                    ),
                );
                self.retain_undecoded(raw_frame, options);
                return ExchangeProcessOutcome::Continue;
            }
        };
        let integrity_failure = decoded.diagnostics.iter().any(|diagnostic| {
            diagnostic.code.contains("checksum")
                && diagnostic.severity != packetcraftr_packet::diagnostic::DiagnosticSeverity::Info
        });
        if Instant::now() >= deadline {
            return self.expire_decoded(decoded, options);
        }
        if integrity_failure {
            push_diagnostic_once(
                &mut self.diagnostics,
                packetcraftr_packet::diagnostic::Diagnostic::warning(
                    "exchange.integrity_rejected",
                    "a response with failed checksum validation was not correlated",
                ),
            );
            self.retain_unsolicited(
                decoded,
                options,
                unsolicited_freshness(received_at, sent_at, deadline),
            );
            return ExchangeProcessOutcome::Continue;
        }

        if received_at.is_none() {
            push_diagnostic_once(
                &mut self.diagnostics,
                packetcraftr_packet::diagnostic::Diagnostic::warning(
                    "capture.ingress_time_unavailable",
                    "a capture provider returned a frame without an ingress marker; the frame was retained but not correlated",
                ),
            );
        }

        let mut matched: Option<(usize, packetcraftr_packet::matcher::MatchResult)> = None;
        for (request_index, prepared_request) in prepared.iter().take(sent_at.len()).enumerate() {
            if Instant::now() >= deadline {
                return self.expire_decoded(decoded, options);
            }
            let Some(received_at) = received_at else {
                continue;
            };
            if received_at < sent_at[request_index] || received_at > deadline {
                continue;
            }
            let mut result = None;
            for layer in prepared_request.built.packet.iter() {
                if Instant::now() >= deadline {
                    return self.expire_decoded(decoded, options);
                }
                let Some(matcher) = registry.matcher(layer.protocol_id().as_str()) else {
                    continue;
                };
                let candidate = matcher.matches(&prepared_request.built.packet, &decoded.packet);
                if Instant::now() >= deadline {
                    return self.expire_decoded(decoded, options);
                }
                if candidate.matched
                    && result.as_ref().is_none_or(
                        |best: &packetcraftr_packet::matcher::MatchResult| {
                            candidate.confidence > best.confidence
                        },
                    )
                {
                    result = Some(candidate);
                }
            }
            if Instant::now() >= deadline {
                return self.expire_decoded(decoded, options);
            }
            let Some(result) = result else {
                continue;
            };
            let replace = matched.as_ref().is_none_or(|(best_index, best)| {
                result.confidence > best.confidence
                    || (result.confidence == best.confidence
                        && self.response_counts[request_index] < self.response_counts[*best_index])
                    || (result.confidence == best.confidence
                        && self.response_counts[request_index] == self.response_counts[*best_index]
                        && request_index < *best_index)
            });
            if replace {
                matched = Some((request_index, result));
            }
        }
        if Instant::now() >= deadline {
            return self.expire_decoded(decoded, options);
        }

        if let Some((request_index, _)) = matched {
            let received_at = received_at.expect("only timestamped capture frames can match");
            if Instant::now() >= deadline {
                return self.expire_decoded(decoded, options);
            }
            if self.responses.len() >= options.max_responses {
                push_diagnostic_once(
                    &mut self.diagnostics,
                    packetcraftr_packet::diagnostic::Diagnostic::warning(
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
                return self.expire_decoded(decoded, options);
            }
            if reserve_capture_evidence(
                &mut self.retained_frames,
                &mut self.retained_bytes,
                decoded.original.len(),
                options.max_capture_queue_frames,
                options.max_captured_bytes,
                &mut self.diagnostics,
            ) {
                self.response_counts[request_index] += 1;
                self.responses.push(MatchedResponse {
                    request_index,
                    response: decoded,
                    latency: received_at.saturating_duration_since(sent_at[request_index]),
                });
            }
        } else {
            if sent_at.len() < prepared.len() {
                push_diagnostic_once(
                    &mut self.diagnostics,
                    packetcraftr_packet::diagnostic::Diagnostic::info(
                        "exchange.pre_send_frame",
                        "a captured frame arrived before one or more requests were sent and was not correlated to those requests",
                    ),
                );
            }
            self.retain_unsolicited(
                decoded,
                options,
                unsolicited_freshness(received_at, sent_at, deadline),
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
            sent_at,
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
            let mut winner = None;
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
                if matched
                    && winner.is_none_or(|best_index| {
                        self.response_counts[request_index] < self.response_counts[best_index]
                    })
                {
                    winner = Some(request_index);
                }
            }
            let Some(request_index) = winner else {
                self.unsolicited.push(decoded);
                self.unsolicited_freshness.push(Some(freshness));
                continue;
            };
            self.response_counts[request_index] += 1;
            self.responses.push(MatchedResponse {
                request_index,
                response: decoded,
                latency: freshness
                    .received_at
                    .saturating_duration_since(sent_at[request_index]),
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
            packetcraftr_packet::diagnostic::Diagnostic::warning(
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
            packetcraftr_packet::diagnostic::Diagnostic::warning(
                "exchange.correlation_deadline",
                "response correlation stopped at the bounded exchange deadline",
            ),
        );
    }

    fn expire_decoded(
        &mut self,
        decoded: DecodedPacket,
        options: &ExchangeOptions,
    ) -> ExchangeProcessOutcome {
        self.mark_correlation_deadline_expired();
        self.retain_unsolicited(decoded, options, None);
        ExchangeProcessOutcome::CorrelationDeadlineExpired
    }

    fn retain_unsolicited(
        &mut self,
        decoded: DecodedPacket,
        options: &ExchangeOptions,
        freshness: Option<UnsolicitedFreshness>,
    ) {
        if self.unsolicited.len() + self.undecoded.len() >= options.max_unsolicited {
            push_diagnostic_once(
                &mut self.diagnostics,
                packetcraftr_packet::diagnostic::Diagnostic::warning(
                    "exchange.unsolicited_limit",
                    format!(
                        "unsolicited frame limit {} reached; later frames were not retained",
                        options.max_unsolicited
                    ),
                ),
            );
            return;
        }
        if reserve_capture_evidence(
            &mut self.retained_frames,
            &mut self.retained_bytes,
            decoded.original.len(),
            options.max_capture_queue_frames,
            options.max_captured_bytes,
            &mut self.diagnostics,
        ) {
            self.unsolicited.push(decoded);
            self.unsolicited_freshness.push(freshness);
        }
    }

    fn retain_undecoded(&mut self, frame: Frame, options: &ExchangeOptions) {
        if self.unsolicited.len() + self.undecoded.len() >= options.max_unsolicited {
            push_diagnostic_once(
                &mut self.diagnostics,
                packetcraftr_packet::diagnostic::Diagnostic::warning(
                    "exchange.unsolicited_limit",
                    format!(
                        "unsolicited/undecoded frame limit {} reached; later frames were not retained",
                        options.max_unsolicited
                    ),
                ),
            );
            return;
        }
        if reserve_capture_evidence(
            &mut self.retained_frames,
            &mut self.retained_bytes,
            frame.bytes().len(),
            options.max_capture_queue_frames,
            options.max_captured_bytes,
            &mut self.diagnostics,
        ) {
            self.undecoded.push(frame);
        }
    }

    pub(crate) fn finish(
        self,
        sent: Vec<BuiltPacket>,
        sent_evidence: Vec<Frame>,
        unanswered: Vec<usize>,
        stats: Stats,
    ) -> ExchangeResult {
        debug_assert_eq!(self.unsolicited.len(), self.unsolicited_freshness.len());
        ExchangeResult {
            sent,
            sent_evidence,
            responses: self.responses,
            unanswered,
            unsolicited: self.unsolicited,
            undecoded: self.undecoded,
            diagnostics: self.diagnostics,
            stats,
        }
    }
}

fn unsolicited_freshness(
    received_at: Option<Instant>,
    sent_at: &[Instant],
    deadline: Instant,
) -> Option<UnsolicitedFreshness> {
    let received_at = received_at.filter(|received_at| *received_at <= deadline)?;
    let eligible_requests = sent_at.partition_point(|sent| *sent <= received_at);
    (eligible_requests != 0).then_some(UnsolicitedFreshness {
        received_at,
        eligible_requests,
    })
}
