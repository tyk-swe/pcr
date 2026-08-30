// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture readiness, bounded draining, and post-send collection.

use std::time::{Duration, Instant};

use packetcraftr_netio::{Error as LiveIoError, capture::Session};

use super::transaction::OperationError;
use super::transaction::Transaction;
use super::{
    ProcessContext, ProcessOutcome, WorkflowPromotionContext, WorkflowResponseMatcher,
    WorkflowStopPredicate,
};

impl<C: Session> Transaction<C> {
    pub(super) fn collect_remaining<F>(
        &mut self,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<(), OperationError>
    where
        F: FnMut(super::Event) -> Result<(), crate::BoundaryError>,
    {
        if !self.correlation_stopped {
            while let Some(remaining) = self.deadline.checked_duration_since(Instant::now()) {
                let Some(frame) = self.capture.inner.next_captured_frame(remaining)? else {
                    break;
                };
                match self.process_frame(frame, workflow_matcher, stop_predicate, emit)? {
                    ProcessOutcome::StopCapture => return Ok(()),
                    ProcessOutcome::CorrelationDeadlineExpired => break,
                    ProcessOutcome::DuplicateRecordIdentity => {
                        return Err(LiveIoError::Capture {
                            message:
                                "capture provider returned the same ingress record more than once"
                                    .to_owned(),
                        }
                        .into());
                    }
                    ProcessOutcome::Continue => {}
                }
            }
        }
        let _ = self.drain(None, workflow_matcher, stop_predicate, emit)?;
        Ok(())
    }

    pub(super) fn drain<F>(
        &mut self,
        enforced_deadline: Option<Instant>,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<ProcessOutcome, OperationError>
    where
        F: FnMut(super::Event) -> Result<(), crate::BoundaryError>,
    {
        for _ in 0..self.capture_limits.max_frames {
            Self::ensure_drain_deadline(enforced_deadline)?;
            let Some(frame) = self.capture.inner.next_captured_frame(Duration::ZERO)? else {
                return Ok(ProcessOutcome::Continue);
            };
            let outcome = self.process_frame(frame, workflow_matcher, stop_predicate, emit)?;
            if outcome == ProcessOutcome::StopCapture {
                return Ok(outcome);
            }
            if outcome == ProcessOutcome::CorrelationDeadlineExpired {
                if enforced_deadline.is_some() {
                    return Err(drain_deadline_error().into());
                }
                return Ok(outcome);
            }
            if outcome == ProcessOutcome::DuplicateRecordIdentity {
                return Err(LiveIoError::Capture {
                    message: "capture provider returned the same ingress record more than once"
                        .to_owned(),
                }
                .into());
            }
        }
        packetcraftr_core::diagnostic::push_once(
            &mut self.captured.diagnostics,
            packetcraftr_core::diagnostic::Diagnostic::warning(
                "exchange.drain_limit",
                format!(
                    "zero-time capture drain stopped after the bounded {} frame(s)",
                    self.capture_limits.max_frames
                ),
            ),
        );
        self.publish_diagnostics(emit)?;
        Ok(ProcessOutcome::Continue)
    }

    fn process_frame<F>(
        &mut self,
        frame: packetcraftr_netio::capture::Captured,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<ProcessOutcome, OperationError>
    where
        F: FnMut(super::Event) -> Result<(), crate::BoundaryError>,
    {
        let context = ProcessContext {
            registry: &self.registry,
            dissector: &self.dissector,
            prepared: &self.prepared,
            sent: &self.sent,
            deadline: self.deadline,
            options: &self.options,
        };
        let processed = self.captured.process(frame, context);
        let promoted = self.promote_workflow(workflow_matcher);
        let stop_requested = self.workflow_stop_requested(stop_predicate);
        self.publish_diagnostics(emit)?;
        for event in self.captured.drain_events() {
            emit(event).map_err(OperationError::output)?;
        }
        if processed == ProcessOutcome::DuplicateRecordIdentity {
            return Ok(processed);
        }
        if stop_requested {
            return Ok(ProcessOutcome::StopCapture);
        }
        if processed == ProcessOutcome::CorrelationDeadlineExpired
            || promoted == ProcessOutcome::CorrelationDeadlineExpired
        {
            return Ok(ProcessOutcome::CorrelationDeadlineExpired);
        }
        Ok(ProcessOutcome::Continue)
    }

    fn workflow_stop_requested(
        &self,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
    ) -> bool {
        let Some(stop_predicate) = stop_predicate.as_deref_mut() else {
            return false;
        };
        // Response events are created only for decoded frames whose ingress
        // marker proves they followed the corresponding completed send. By
        // waiting for the event, a stop can never discard its own evidence.
        self.captured.pending_events.iter().any(|event| {
            let super::Event::Response(response) = event else {
                return false;
            };
            let request = &self
                .prepared
                .get(response.request_index)
                .expect("retained response indices identify prepared requests")
                .built
                .packet;
            stop_predicate(response.request_index, request, &response.response)
        })
    }

    pub(super) fn promote_workflow(
        &mut self,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> ProcessOutcome {
        let Some(matches_request) = workflow_matcher.as_deref_mut() else {
            self.captured.finalize_unsolicited();
            return ProcessOutcome::Continue;
        };
        let context = WorkflowPromotionContext {
            prepared: &self.prepared,
            sent: &self.sent,
            deadline: self.deadline,
            max_responses: self.options.max_responses,
        };
        self.captured
            .promote_workflow_unsolicited(context, matches_request)
    }

    fn ensure_drain_deadline(enforced_deadline: Option<Instant>) -> Result<(), OperationError> {
        if enforced_deadline
            .is_some_and(|deadline| deadline.checked_duration_since(Instant::now()).is_none())
        {
            return Err(drain_deadline_error().into());
        }
        Ok(())
    }

    pub(super) fn publish_diagnostics<F>(&mut self, emit: &mut F) -> Result<(), OperationError>
    where
        F: FnMut(super::Event) -> Result<(), crate::BoundaryError>,
    {
        #[expect(
            clippy::indexing_slicing,
            reason = "`published_diagnostics` only ever counts diagnostics already emitted \
                      from this append-only vector, so it stays within `diagnostics.len()`"
        )]
        let diagnostics = self.captured.diagnostics[self.published_diagnostics..].to_vec();
        for diagnostic in diagnostics {
            emit(super::Event::Diagnostic(diagnostic)).map_err(OperationError::output)?;
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "one increment per diagnostic in the vector, so the count cannot exceed \
                          `diagnostics.len()`"
            )]
            {
                self.published_diagnostics += 1;
            }
        }
        Ok(())
    }
}

fn drain_deadline_error() -> LiveIoError {
    LiveIoError::DeadlineExceeded {
        operation: "draining capture before all requests were sent",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
    use packetcraftr_core::{Packet, decode::DecodedPacket};
    use packetcraftr_netio::capture::{Captured, Metadata, Statistics};
    use packetcraftr_netio::interface::Id as InterfaceId;
    use packetcraftr_netio::transmit::{Frame as TransmissionFrame, Report};

    use super::*;
    use crate::exchange::{
        Event, Prepared, PreparedPacket, WorkflowResponseMatcher, WorkflowStopPredicate,
    };

    struct CaptureState {
        sends: AtomicUsize,
        deliver_only_when_blocking: bool,
        reads: Mutex<Vec<Duration>>,
        frames: Mutex<VecDeque<Frame>>,
        shutdowns: AtomicUsize,
    }

    struct FixtureCapture {
        state: Arc<CaptureState>,
        metadata: Metadata,
    }

    impl Session for FixtureCapture {
        fn metadata(&self) -> &Metadata {
            &self.metadata
        }

        fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
            Ok(())
        }

        fn next_captured_frame(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<Captured>, LiveIoError> {
            self.state.reads.lock().expect("read log").push(timeout);
            if self.state.sends.load(Ordering::SeqCst) == 0
                || (self.state.deliver_only_when_blocking && timeout.is_zero())
            {
                return Ok(None);
            }
            Ok(self
                .state
                .frames
                .lock()
                .expect("capture frames")
                .pop_front()
                .map(|frame| Captured::new(frame, Instant::now())))
        }

        fn shutdown(&mut self) -> Result<(), LiveIoError> {
            self.state.shutdowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn statistics(&self) -> Statistics {
            Statistics::default()
        }
    }

    struct FixtureSender(Arc<CaptureState>);

    impl packetcraftr_netio::transmit::Sender for FixtureSender {
        fn send(&self, frame: TransmissionFrame<'_>) -> Result<Report, LiveIoError> {
            let report = Report::committed(frame.bytes().len(), frame.bytes().clone());
            self.0.sends.fetch_add(1, Ordering::SeqCst);
            Ok(report)
        }
    }

    fn udp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Packet {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source,
                destination,
                ..Ipv4::default()
            })
            .push(Udp {
                source_port,
                destination_port,
                ..Udp::default()
            })
            .push(Raw::new(Bytes::from_static(b"response")));
        packet
    }

    fn fixture_transaction(
        deliver_only_when_blocking: bool,
        request_count: usize,
        max_responses: usize,
    ) -> (
        Transaction<FixtureCapture>,
        FixtureSender,
        Arc<CaptureState>,
    ) {
        let client = Ipv4Addr::new(192, 0, 2, 1);
        let server = Ipv4Addr::new(192, 0, 2, 53);
        let request = udp_packet(client, server, 40_000, 9);
        let response = udp_packet(server, client, 9, 40_000);
        let prepared_evidence = crate::evidence::test_sent_packet(request);
        let prepared_packets = (0..request_count)
            .map(|_| PreparedPacket {
                built: prepared_evidence.built().clone(),
                route: prepared_evidence.route().clone(),
            })
            .collect();
        let response_frame = crate::evidence::test_sent_packet(response).frame().clone();
        let options = crate::exchange::Options {
            max_responses,
            ..crate::exchange::Options::default()
        };
        let capture_limits = options.validate().expect("fixture exchange options");
        let started = Instant::now();
        let deadline = started + Duration::from_secs(1);
        let state = Arc::new(CaptureState {
            sends: AtomicUsize::new(0),
            deliver_only_when_blocking,
            reads: Mutex::new(Vec::new()),
            frames: Mutex::new(VecDeque::from([response_frame])),
            shutdowns: AtomicUsize::new(0),
        });
        let capture = FixtureCapture {
            state: Arc::clone(&state),
            metadata: Metadata {
                interface: InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 1,
                },
                link_type: LinkType::RAW,
                snap_length: capture_limits.snap_length,
            },
        };
        let prepared = Prepared {
            started,
            deadline,
            capture_limits,
            options,
            packets: prepared_packets,
            packet_count: u64::try_from(request_count).expect("bounded fixture"),
            total_bytes: u64::try_from(prepared_evidence.bytes_sent()).expect("bounded fixture")
                * u64::try_from(request_count).expect("bounded fixture"),
        };
        (
            Transaction::new(
                Arc::new(
                    packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
                ),
                capture,
                prepared,
            ),
            FixtureSender(Arc::clone(&state)),
            state,
        )
    }

    #[test]
    fn stop_predicate_preserves_response_event_and_skips_blocking_collection() {
        let (transaction, sender, state) =
            fixture_transaction(false, 1, crate::exchange::DEFAULT_MAX_RESPONSES);
        let mut matcher = |_: usize, _: &Packet, _: &DecodedPacket| true;
        let matcher: &mut WorkflowResponseMatcher<'_> = &mut matcher;
        let mut stop_calls = 0;
        let mut stop = |request_index: usize, _: &Packet, _: &DecodedPacket| {
            stop_calls += 1;
            assert_eq!(request_index, 0);
            true
        };
        let stop: &mut WorkflowStopPredicate<'_> = &mut stop;
        let mut events = Vec::new();

        let summary = transaction
            .execute(&sender, Some(matcher), Some(stop), &mut |event| {
                events.push(event);
                Ok(())
            })
            .expect("early-stopped exchange");

        assert_eq!(stop_calls, 1);
        assert!(matches!(
            events[0],
            Event::Sent {
                request_index: 0,
                ..
            }
        ));
        assert!(matches!(events[1], Event::Response(_)));
        assert_eq!(events.len(), 2);
        assert!(summary.unanswered.is_empty());
        assert_eq!(summary.stats.packets_completed, 1);
        assert_eq!(
            *state.reads.lock().expect("read log"),
            [Duration::ZERO, Duration::ZERO],
            "a stop found by the post-send drain must bypass blocking collection"
        );
        assert_eq!(state.shutdowns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn blocking_collection_stop_skips_the_final_zero_time_drain() {
        let (transaction, sender, state) =
            fixture_transaction(true, 1, crate::exchange::DEFAULT_MAX_RESPONSES);
        let mut matcher = |_: usize, _: &Packet, _: &DecodedPacket| true;
        let matcher: &mut WorkflowResponseMatcher<'_> = &mut matcher;
        let mut stop = |_: usize, _: &Packet, _: &DecodedPacket| true;
        let stop: &mut WorkflowStopPredicate<'_> = &mut stop;
        let mut events = Vec::new();

        let summary = transaction
            .execute(&sender, Some(matcher), Some(stop), &mut |event| {
                events.push(event);
                Ok(())
            })
            .expect("early-stopped exchange");

        assert!(matches!(events.last(), Some(Event::Response(_))));
        assert!(summary.unanswered.is_empty());
        let reads = state.reads.lock().expect("read log");
        assert_eq!(reads.len(), 3);
        assert_eq!(reads[0], Duration::ZERO);
        assert_eq!(reads[1], Duration::ZERO);
        assert!(reads[2] > Duration::ZERO);
        assert_eq!(state.shutdowns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unretained_response_does_not_trigger_stop() {
        let (transaction, sender, state) = fixture_transaction(false, 1, 0);
        let mut matcher = |_: usize, _: &Packet, _: &DecodedPacket| true;
        let matcher: &mut WorkflowResponseMatcher<'_> = &mut matcher;
        let mut stop_calls = 0;
        let mut stop = |_: usize, _: &Packet, _: &DecodedPacket| {
            stop_calls += 1;
            true
        };
        let stop: &mut WorkflowStopPredicate<'_> = &mut stop;
        let mut events = Vec::new();

        let summary = transaction
            .execute(&sender, Some(matcher), Some(stop), &mut |event| {
                events.push(event);
                Ok(())
            })
            .expect("bounded exchange without a retained response");

        assert_eq!(stop_calls, 0);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Response(_)))
        );
        assert_eq!(summary.unanswered, [0]);
        assert_eq!(state.reads.lock().expect("read log").len(), 5);
    }

    #[test]
    fn early_stop_cancels_unsent_requests_without_incoherent_events_or_stats() {
        let (transaction, sender, state) =
            fixture_transaction(false, 2, crate::exchange::DEFAULT_MAX_RESPONSES);
        let mut matcher = |_: usize, _: &Packet, _: &DecodedPacket| true;
        let matcher: &mut WorkflowResponseMatcher<'_> = &mut matcher;
        let mut stop = |_: usize, _: &Packet, _: &DecodedPacket| true;
        let stop: &mut WorkflowStopPredicate<'_> = &mut stop;
        let mut collector = crate::exchange::Collector::default();

        let summary = transaction
            .execute(&sender, Some(matcher), Some(stop), &mut |event| {
                collector.observe(event);
                Ok(())
            })
            .expect("early-stopped multi-request exchange");

        assert_eq!(state.sends.load(Ordering::SeqCst), 1);
        assert!(summary.unanswered.is_empty());
        assert_eq!(summary.stats.packets_attempted, 1);
        assert_eq!(summary.stats.packets_completed, 1);
        let result = collector
            .finish(summary)
            .expect("cancelled unsent requests must not create orphan events");
        assert_eq!(result.sent.len(), 1);
        assert_eq!(result.responses.len(), 1);
        assert_eq!(
            result.stats.bytes,
            u64::try_from(result.sent[0].bytes_sent()).expect("bounded fixture")
        );
    }
}
