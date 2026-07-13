pub const DEFAULT_MAX_UNSOLICITED_FRAMES: usize = DEFAULT_CAPTURE_QUEUE_FRAMES;
pub const MAX_EXCHANGE_TIMEOUT: Duration = MAX_CAPTURE_TIMEOUT;

struct CaptureGuard<C: CaptureSession> {
    inner: C,
    shutdown_attempted: bool,
}

impl<C: CaptureSession> CaptureGuard<C> {
    fn new(inner: C) -> Self {
        Self {
            inner,
            shutdown_attempted: false,
        }
    }

    fn wait_ready(&mut self, timeout: Duration) -> Result<(), LiveIoError> {
        self.inner.wait_ready(timeout)
    }

    fn next_captured_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<CapturedFrame>, LiveIoError> {
        self.inner.next_captured_frame(timeout)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.shutdown_attempted = true;
        self.inner.shutdown()
    }

    fn statistics(&self) -> CaptureStatistics {
        self.inner.statistics()
    }
}

impl<C: CaptureSession> Drop for CaptureGuard<C> {
    fn drop(&mut self) {
        if !self.shutdown_attempted {
            self.shutdown_attempted = true;
            let _ = self.inner.shutdown();
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
    pub diagnostics: Vec<crate::packet::internal::Diagnostic>,
    pub stats: OperationStats,
}

struct ExchangeAccumulator {
    responses: Vec<MatchedResponse>,
    unsolicited: Vec<DecodedPacket>,
    undecoded: Vec<Frame>,
    diagnostics: Vec<crate::packet::internal::Diagnostic>,
    retained_frames: usize,
    retained_bytes: usize,
    response_counts: Vec<usize>,
}

struct PlannedExchangePacket {
    packet: Packet,
    plan: PlannedRoute,
    build_context: BuildContext,
    preliminary_build: BuiltPacket,
}

struct PreparedExchangePacket {
    built: BuiltPacket,
    route: MaterializedRoute,
}

#[derive(Clone, Copy)]
struct ExchangeProcessContext<'a> {
    registry: &'a ProtocolRegistry,
    dissector: &'a Dissector,
    prepared: &'a [PreparedExchangePacket],
    sent_at: &'a [Instant],
    deadline: Instant,
    options: &'a ExchangeOptions,
}

fn drain_available<C: CaptureSession>(
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
        captured.process(frame, context);
    }
    push_diagnostic_once(
        &mut captured.diagnostics,
        crate::packet::internal::Diagnostic::warning(
            "exchange.drain_limit",
            format!("zero-time capture drain stopped after the bounded {frame_limit} frame(s)"),
        ),
    );
    Ok(())
}

impl ExchangeAccumulator {
    fn new(requests: usize) -> Self {
        Self {
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            retained_frames: 0,
            retained_bytes: 0,
            response_counts: vec![0; requests],
        }
    }

    fn process(&mut self, captured: CapturedFrame, context: ExchangeProcessContext<'_>) {
        let ExchangeProcessContext {
            registry,
            dissector,
            prepared,
            sent_at,
            deadline,
            options,
        } = context;
        let CapturedFrame { frame, received_at } = captured;
        let raw_frame = frame.clone();
        let decoded = match dissector.decode(frame, options.decode.clone()) {
            Ok(decoded) => decoded,
            Err(error) => {
                push_diagnostic_once(
                    &mut self.diagnostics,
                    crate::packet::internal::Diagnostic::warning(
                        "exchange.decode_error",
                        format!("captured frame could not be decoded: {error}"),
                    ),
                );
                self.retain_undecoded(raw_frame, options);
                return;
            }
        };
        let integrity_failure = decoded.diagnostics.iter().any(|diagnostic| {
            diagnostic.code.contains("checksum")
                && diagnostic.severity != crate::packet::internal::DiagnosticSeverity::Info
        });
        if integrity_failure {
            push_diagnostic_once(
                &mut self.diagnostics,
                crate::packet::internal::Diagnostic::warning(
                    "exchange.integrity_rejected",
                    "a response with failed checksum validation was not correlated",
                ),
            );
            self.retain_unsolicited(decoded, options);
            return;
        }

        if received_at.is_none() {
            push_diagnostic_once(
                &mut self.diagnostics,
                crate::packet::internal::Diagnostic::warning(
                    "capture.ingress_time_unavailable",
                    "a capture provider returned a frame without an ingress marker; the frame was retained but not correlated",
                ),
            );
        }

        let mut matched: Option<(usize, crate::packet::internal::MatchResult)> = None;
        for (request_index, prepared_request) in prepared.iter().take(sent_at.len()).enumerate() {
            let Some(received_at) = received_at else {
                continue;
            };
            if received_at < sent_at[request_index] || received_at > deadline {
                continue;
            }
            let result = prepared_request
                .built
                .packet
                .iter()
                .filter_map(|layer| registry.matcher(&layer.protocol_id()))
                .map(|matcher| matcher.matches(&prepared_request.built.packet, &decoded.packet))
                .filter(|result| result.matched)
                .max_by_key(|result| result.confidence);
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

        if let Some((request_index, _)) = matched {
            let received_at = received_at.expect("only timestamped capture frames can match");
            if self.responses.len() >= options.max_responses {
                push_diagnostic_once(
                    &mut self.diagnostics,
                    crate::packet::internal::Diagnostic::warning(
                        "exchange.response_limit",
                        format!(
                            "matched response limit {} reached; later responses were not retained",
                            options.max_responses
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
                    crate::packet::internal::Diagnostic::info(
                        "exchange.pre_send_frame",
                        "a captured frame arrived before one or more requests were sent and was not correlated to those requests",
                    ),
                );
            }
            self.retain_unsolicited(decoded, options);
        }
    }

    fn retain_unsolicited(&mut self, decoded: DecodedPacket, options: &ExchangeOptions) {
        if self.unsolicited.len() + self.undecoded.len() >= options.max_unsolicited {
            push_diagnostic_once(
                &mut self.diagnostics,
                crate::packet::internal::Diagnostic::warning(
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
        }
    }

    fn retain_undecoded(&mut self, frame: Frame, options: &ExchangeOptions) {
        if self.unsolicited.len() + self.undecoded.len() >= options.max_unsolicited {
            push_diagnostic_once(
                &mut self.diagnostics,
                crate::packet::internal::Diagnostic::warning(
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
            frame.bytes.len(),
            options.max_capture_queue_frames,
            options.max_captured_bytes,
            &mut self.diagnostics,
        ) {
            self.undecoded.push(frame);
        }
    }
}
