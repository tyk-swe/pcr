use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use crate::capture::Frame;
use crate::net::{
    Error as LiveIoError,
    capture::{
        CaptureOverflowPolicy, CaptureSession, CaptureStatistics, CapturedFrame,
        DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES,
    },
    route::{MaterializedRoute, PlannedRoute},
};
use crate::packet::{
    Packet,
    build::{BuildContext, BuiltPacket},
    decode::{DecodeOptions, DecodedPacket, Dissector},
    registry::ProtocolRegistry,
    template::DEFAULT_MAX_TEMPLATE_PACKETS,
};

use super::super::Stats;
use super::super::helpers::{push_diagnostic_once, reserve_capture_evidence};
use super::super::send::SendOptions;

pub const DEFAULT_MAX_UNSOLICITED_FRAMES: usize = DEFAULT_CAPTURE_QUEUE_FRAMES;
pub const MAX_EXCHANGE_TIMEOUT: Duration = crate::net::capture::MAX_TIMEOUT;

pub(crate) enum CaptureShutdownState {
    NotAttempted,
    Succeeded,
    Failed(LiveIoError),
}

pub(crate) struct CaptureGuard<C: CaptureSession> {
    inner: C,
    shutdown_state: CaptureShutdownState,
}

impl<C: CaptureSession> CaptureGuard<C> {
    pub(crate) fn new(inner: C) -> Self {
        Self {
            inner,
            shutdown_state: CaptureShutdownState::NotAttempted,
        }
    }

    pub(crate) fn supports_monotonic_ingress_time(&self) -> bool {
        self.inner.supports_monotonic_ingress_time()
    }

    pub(crate) fn wait_ready(&mut self, timeout: Duration) -> Result<(), LiveIoError> {
        self.inner.wait_ready(timeout)
    }

    pub(crate) fn next_captured_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<CapturedFrame>, LiveIoError> {
        self.inner.next_captured_frame(timeout)
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), LiveIoError> {
        match &self.shutdown_state {
            CaptureShutdownState::Succeeded => return Ok(()),
            CaptureShutdownState::Failed(error) => return Err(error.clone()),
            CaptureShutdownState::NotAttempted => {}
        }

        // Mark completion before entering provider code so a panic cannot make
        // Drop invoke an unknown backend state a second time.
        self.shutdown_state = CaptureShutdownState::Succeeded;
        let result = match catch_unwind(AssertUnwindSafe(|| self.inner.shutdown())) {
            Ok(result) => result,
            Err(_) => Err(LiveIoError::Capture {
                message: "capture provider panicked during shutdown".to_owned(),
            }),
        };
        if let Err(error) = &result {
            self.shutdown_state = CaptureShutdownState::Failed(error.clone());
        }
        result
    }

    pub(crate) fn statistics(&self) -> CaptureStatistics {
        self.inner.statistics()
    }
}

impl<C: CaptureSession> Drop for CaptureGuard<C> {
    fn drop(&mut self) {
        if matches!(self.shutdown_state, CaptureShutdownState::NotAttempted) {
            let _ = self.shutdown();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeOptions {
    pub send: SendOptions,
    pub timeout: Duration,
    pub max_template_packets: usize,
    pub max_unsolicited: usize,
    pub max_responses: usize,
    /// One aggregate backend queue bound shared by matched, unsolicited, and
    /// undecodable capture traffic.
    pub max_capture_queue_frames: usize,
    pub max_captured_bytes: usize,
    pub capture_overflow_policy: CaptureOverflowPolicy,
    pub decode: DecodeOptions,
}

impl Default for ExchangeOptions {
    fn default() -> Self {
        Self {
            send: SendOptions::default(),
            timeout: Duration::from_secs(3),
            max_template_packets: DEFAULT_MAX_TEMPLATE_PACKETS,
            max_unsolicited: DEFAULT_MAX_UNSOLICITED_FRAMES,
            max_responses: DEFAULT_MAX_UNSOLICITED_FRAMES,
            max_capture_queue_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_captured_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            capture_overflow_policy: CaptureOverflowPolicy::Fail,
            decode: DecodeOptions::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MatchedResponse {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct ExchangeResult {
    pub sent: Vec<BuiltPacket>,
    /// Timestamped exact frames accepted by the send provider. Layer 2 sends
    /// retain the planned link type; raw Layer 3 sends use DLT_RAW so the
    /// evidence can be written to a capture stream without inventing an
    /// Ethernet envelope.
    pub sent_evidence: Vec<Frame>,
    pub responses: Vec<MatchedResponse>,
    pub unanswered: Vec<usize>,
    pub unsolicited: Vec<DecodedPacket>,
    /// Captured records whose bytes could not be decoded under the configured
    /// limits. The complete raw frame is retained for evidence.
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<crate::packet::diagnostic::Diagnostic>,
    pub stats: Stats,
}

#[derive(Clone, Copy)]
struct UnsolicitedFreshness {
    received_at: Instant,
    eligible_requests: usize,
}

pub(crate) type WorkflowResponseMatcher<'a> =
    dyn FnMut(usize, &Packet, &DecodedPacket) -> bool + 'a;

pub(crate) struct ExchangeAccumulator {
    pub(in crate::client) responses: Vec<MatchedResponse>,
    pub(in crate::client) unsolicited: Vec<DecodedPacket>,
    pub(in crate::client) undecoded: Vec<Frame>,
    pub(in crate::client) diagnostics: Vec<crate::packet::diagnostic::Diagnostic>,
    unsolicited_freshness: Vec<Option<UnsolicitedFreshness>>,
    retained_frames: usize,
    retained_bytes: usize,
    pub(in crate::client) response_counts: Vec<usize>,
    correlation_deadline_expired: bool,
    workflow_examined_unsolicited: usize,
}

pub(crate) struct PlannedExchangePacket {
    pub(in crate::client) packet: Packet,
    pub(in crate::client) plan: PlannedRoute,
    pub(in crate::client) build_context: BuildContext,
    pub(in crate::client) preliminary_build: BuiltPacket,
}

pub(crate) struct PreparedExchangePacket {
    pub(in crate::client) built: BuiltPacket,
    pub(in crate::client) route: MaterializedRoute,
}

#[derive(Clone, Copy)]
pub(crate) struct ExchangeProcessContext<'a> {
    pub(in crate::client) registry: &'a ProtocolRegistry,
    pub(in crate::client) dissector: &'a Dissector,
    pub(in crate::client) prepared: &'a [PreparedExchangePacket],
    pub(in crate::client) sent_at: &'a [Instant],
    pub(in crate::client) deadline: Instant,
    pub(in crate::client) options: &'a ExchangeOptions,
}

#[derive(Clone, Copy)]
pub(crate) struct WorkflowPromotionContext<'a> {
    pub(in crate::client) prepared: &'a [PreparedExchangePacket],
    pub(in crate::client) sent_at: &'a [Instant],
    pub(in crate::client) deadline: Instant,
    pub(in crate::client) max_responses: usize,
}

pub(crate) fn drain_available<C: CaptureSession>(
    capture: &mut CaptureGuard<C>,
    enforced_deadline: Option<Instant>,
    frame_limit: usize,
    captured: &mut ExchangeAccumulator,
    context: ExchangeProcessContext<'_>,
) -> Result<(), LiveIoError> {
    for _ in 0..frame_limit {
        if enforced_deadline
            .is_some_and(|deadline| deadline.checked_duration_since(Instant::now()).is_none())
        {
            return Err(LiveIoError::DeadlineExceeded {
                operation: "draining capture before all requests were sent",
            });
        }
        let Some(frame) = capture.next_captured_frame(Duration::ZERO)? else {
            return Ok(());
        };
        if captured.process(frame, context) == ExchangeProcessOutcome::CorrelationDeadlineExpired {
            if enforced_deadline.is_some() {
                return Err(LiveIoError::DeadlineExceeded {
                    operation: "draining capture before all requests were sent",
                });
            }
            return Ok(());
        }
    }
    push_diagnostic_once(
        &mut captured.diagnostics,
        crate::packet::diagnostic::Diagnostic::warning(
            "exchange.drain_limit",
            format!("zero-time capture drain stopped after the bounded {frame_limit} frame(s)"),
        ),
    );
    Ok(())
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
                    crate::packet::diagnostic::Diagnostic::warning(
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
                && diagnostic.severity != crate::packet::diagnostic::DiagnosticSeverity::Info
        });
        if Instant::now() >= deadline {
            return self.expire_decoded(decoded, options);
        }
        if integrity_failure {
            push_diagnostic_once(
                &mut self.diagnostics,
                crate::packet::diagnostic::Diagnostic::warning(
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
                crate::packet::diagnostic::Diagnostic::warning(
                    "capture.ingress_time_unavailable",
                    "a capture provider returned a frame without an ingress marker; the frame was retained but not correlated",
                ),
            );
        }

        let mut matched: Option<(usize, crate::packet::matcher::MatchResult)> = None;
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
                let Some(matcher) = registry.matcher(&layer.protocol_id()) else {
                    continue;
                };
                let candidate = matcher.matches(&prepared_request.built.packet, &decoded.packet);
                if Instant::now() >= deadline {
                    return self.expire_decoded(decoded, options);
                }
                if candidate.matched
                    && result
                        .as_ref()
                        .is_none_or(|best: &crate::packet::matcher::MatchResult| {
                            candidate.confidence > best.confidence
                        })
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
                    crate::packet::diagnostic::Diagnostic::warning(
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
                    crate::packet::diagnostic::Diagnostic::info(
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

    pub(in crate::client) fn promote_workflow_unsolicited(
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
        if self.stop_workflow_promotion_if_deadline_expired(deadline) {
            return ExchangeProcessOutcome::CorrelationDeadlineExpired;
        }
        if self.workflow_response_limit_reached(max_responses) {
            self.workflow_examined_unsolicited = self.unsolicited.len();
            return ExchangeProcessOutcome::Continue;
        }

        let candidates = self
            .unsolicited
            .split_off(self.workflow_examined_unsolicited);
        let candidate_freshness = self
            .unsolicited_freshness
            .split_off(self.workflow_examined_unsolicited);
        for (decoded, freshness) in candidates.into_iter().zip(candidate_freshness) {
            let Some(freshness) = freshness else {
                continue;
            };
            if self.workflow_response_limit_reached(max_responses) {
                self.unsolicited.push(decoded);
                self.unsolicited_freshness.push(Some(freshness));
                continue;
            }
            let mut matching_requests = Vec::new();
            for (request_index, prepared_request) in prepared
                .iter()
                .enumerate()
                .take(freshness.eligible_requests)
            {
                if self.stop_workflow_promotion_if_deadline_expired(deadline) {
                    return ExchangeProcessOutcome::CorrelationDeadlineExpired;
                }
                let matched =
                    matches_request(request_index, &prepared_request.built.packet, &decoded);
                if self.stop_workflow_promotion_if_deadline_expired(deadline) {
                    return ExchangeProcessOutcome::CorrelationDeadlineExpired;
                }
                if matched {
                    matching_requests.push(request_index);
                }
            }
            if matching_requests.is_empty() && freshness.eligible_requests == prepared.len() {
                self.unsolicited.push(decoded);
                self.unsolicited_freshness.push(Some(freshness));
                continue;
            }
            for request_index in matching_requests {
                if self.workflow_response_limit_reached(max_responses) {
                    break;
                }
                if self.stop_workflow_promotion_if_deadline_expired(deadline) {
                    return ExchangeProcessOutcome::CorrelationDeadlineExpired;
                }
                self.response_counts[request_index] += 1;
                self.responses.push(MatchedResponse {
                    request_index,
                    response: decoded.clone(),
                    latency: freshness
                        .received_at
                        .saturating_duration_since(sent_at[request_index]),
                });
            }
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
            crate::packet::diagnostic::Diagnostic::warning(
                "exchange.response_limit",
                format!(
                    "matched response limit {max_responses} reached; later responses were not retained"
                ),
            ),
        );
        true
    }

    fn stop_workflow_promotion_if_deadline_expired(&mut self, deadline: Instant) -> bool {
        if Instant::now() < deadline {
            return false;
        }
        self.unsolicited.clear();
        self.unsolicited_freshness.clear();
        self.workflow_examined_unsolicited = 0;
        self.mark_correlation_deadline_expired();
        true
    }

    fn mark_correlation_deadline_expired(&mut self) {
        self.correlation_deadline_expired = true;
        push_diagnostic_once(
            &mut self.diagnostics,
            crate::packet::diagnostic::Diagnostic::warning(
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
                crate::packet::diagnostic::Diagnostic::warning(
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
                crate::packet::diagnostic::Diagnostic::warning(
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

    pub(in crate::client) fn finish(
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
