// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_netio::{Error as LiveIoError, capture::Session};

use super::executor::OperationError;
use super::executor::Transaction;
use super::{ProcessContext, ProcessOutcome, WorkflowResponseMatcher, WorkflowStopPredicate};

#[derive(Clone, Copy)]
pub(super) enum DrainPolicy {
    /// Requests remain to be sent, so the window closing aborts the operation.
    Enforced,
    /// Every request is sent; the window closing just ends correlation.
    BestEffort,
}

impl DrainPolicy {
    const fn is_enforced(self) -> bool {
        matches!(self, Self::Enforced)
    }
}

impl<C: Session> Transaction<C> {
    pub(super) fn collect_remaining<F>(
        &mut self,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<(), OperationError>
    where
        F: FnMut(super::Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        if !self.correlation_stopped {
            while !self.window.expired() {
                let Some(frame) = self
                    .capture
                    .inner
                    .next_captured_frame(self.window.deadline())?
                else {
                    break;
                };
                match self.process_frame(frame, workflow_matcher, stop_predicate, emit)? {
                    ProcessOutcome::StopCapture => return Ok(()),
                    ProcessOutcome::CorrelationDeadlineExpired => break,
                    ProcessOutcome::Continue => {}
                }
            }
        }
        let _ = self.drain(
            DrainPolicy::BestEffort,
            workflow_matcher,
            stop_predicate,
            emit,
        )?;
        Ok(())
    }

    pub(super) fn drain<F>(
        &mut self,
        policy: DrainPolicy,
        workflow_matcher: &mut Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: &mut Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<ProcessOutcome, OperationError>
    where
        F: FnMut(super::Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        let queued = crate::deadline::immediate(self.cancellation.clone());
        for _ in 0..self.collection.capture.max_frames {
            if policy.is_enforced() && self.window.expired() {
                return Err(drain_deadline_error().into());
            }
            let Some(frame) = self.capture.inner.next_captured_frame(&queued)? else {
                return Ok(ProcessOutcome::Continue);
            };
            let outcome = self.process_frame(frame, workflow_matcher, stop_predicate, emit)?;
            if outcome == ProcessOutcome::StopCapture {
                return Ok(outcome);
            }
            if outcome == ProcessOutcome::CorrelationDeadlineExpired {
                if policy.is_enforced() {
                    return Err(drain_deadline_error().into());
                }
                return Ok(outcome);
            }
        }
        self.captured
            .diagnostics
            .push_once(packetcraftr_core::diagnostic::Diagnostic::warning(
                "exchange.drain_limit",
                format!(
                    "zero-time capture drain stopped after the bounded {} frame(s)",
                    self.collection.capture.max_frames
                ),
            ));
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
        F: FnMut(super::Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        let context = ProcessContext {
            registry: &self.registry,
            dissector: &self.dissector,
            request_count: self.request_count,
            sent: &self.sent,
            window: &self.window,
            collection: &self.collection,
        };
        // A duplicated ingress record aborts, so nothing downstream runs for its frame.
        let processed = self
            .captured
            .process(frame, context, workflow_matcher.as_deref_mut())
            .map_err(|duplicate| OperationError::from(duplicate.into_error()))?;
        let promoted = match workflow_matcher.as_deref_mut() {
            Some(matches_request) => self
                .captured
                .promote_workflow_unsolicited(context, matches_request),
            None => {
                self.captured.finalize_unsolicited();
                ProcessOutcome::Continue
            }
        };
        let stop_requested = self.workflow_stop_requested(stop_predicate);
        self.publish_diagnostics(emit)?;
        for event in self.captured.drain_events() {
            emit(event).map_err(OperationError::output)?;
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
        // By waiting for the event, a stop can never discard its own evidence.
        self.captured.pending_events.iter().any(|event| {
            let super::Event::Response(response) = event else {
                return false;
            };
            let request = &self.sent[response.request_index].built().packet;
            stop_predicate(response.request_index, request, &response.response)
        })
    }

    pub(super) fn publish_diagnostics<F>(&mut self, emit: &mut F) -> Result<(), OperationError>
    where
        F: FnMut(super::Event) -> Result<(), packetcraftr_core::error::BoundaryError>,
    {
        self.captured.diagnostics.publish_new(|diagnostic| {
            emit(super::Event::Diagnostic(diagnostic)).map_err(OperationError::output)
        })
    }
}

fn drain_deadline_error() -> LiveIoError {
    LiveIoError::DeadlineExceeded {
        operation: "draining capture before all requests were sent",
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use packetcraftr_core::budget::Deadline;

    use crate::preparation::PreparedPacket;

    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
    use packetcraftr_core::{decode::DecodedPacket, packet::Packet};
    use packetcraftr_netio::capture::{Captured, Metadata, Stats};
    use packetcraftr_netio::interface::Id as InterfaceId;
    use packetcraftr_netio::transmit::{Outbound, Report};

    use super::*;
    use crate::exchange::{Prepared, Window, WorkflowResponseMatcher, WorkflowStopPredicate};

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
        fn supports_ingress_time(&self) -> bool {
            true
        }
        fn metadata(&self) -> &Metadata {
            &self.metadata
        }

        fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), LiveIoError> {
            Ok(())
        }

        fn next_captured_frame(
            &mut self,
            deadline: &Deadline,
        ) -> Result<Option<Captured>, LiveIoError> {
            let timeout = deadline.remaining().unwrap_or_default();
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

        fn stats(&self) -> Stats {
            Stats::default()
        }
    }

    struct FixtureSender(Arc<CaptureState>);

    impl packetcraftr_netio::transmit::Provider for FixtureSender {
        fn send(&self, frame: Outbound<'_>) -> Result<Report, LiveIoError> {
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
        let prepared_evidence = crate::test_support::sent_packet(request);
        let prepared_packets = (0..request_count)
            .map(|_| {
                PreparedPacket::fixture(
                    prepared_evidence.built().clone(),
                    prepared_evidence.route().clone(),
                )
            })
            .collect();
        let response_frame = crate::test_support::sent_packet(response).frame().clone();
        let collection = crate::exchange::Collection {
            max_responses,
            ..crate::exchange::Collection::default()
        };
        collection.validate().expect("fixture exchange collection");
        let snap_length = collection.capture.snap_length;
        let window = Window::open(&crate::clock::SystemClock, Duration::from_secs(1), None)
            .expect("fixture window");
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
                snap_length,
                native: Default::default(),
            },
        };
        let prepared = Prepared {
            cancellation: None,
            window,
            collection,
            packets: prepared_packets,
            packet_count: u64::try_from(request_count).expect("bounded fixture"),
            total_bytes: u64::try_from(prepared_evidence.bytes_sent()).expect("bounded fixture")
                * u64::try_from(request_count).expect("bounded fixture"),
        };
        (
            Transaction::new(
                packetcraftr_core::protocol::builtin::registry(),
                capture,
                prepared,
            ),
            FixtureSender(Arc::clone(&state)),
            state,
        )
    }

    fn unrelated_frame() -> Frame {
        let packet = udp_packet(
            Ipv4Addr::new(198, 51, 100, 7),
            Ipv4Addr::new(203, 0, 113, 9),
            7,
            7,
        );
        crate::test_support::sent_packet(packet).frame().clone()
    }

    #[test]
    fn workflow_exchange_fails_when_a_promotable_frame_was_refused_and_a_request_is_unanswered() {
        let (mut transaction, sender, state) =
            fixture_transaction(false, 1, crate::exchange::DEFAULT_MAX_RESPONSES);
        transaction.collection.max_unmatched_frames = 0;
        *state.frames.lock().expect("capture frames") = VecDeque::from([unrelated_frame()]);
        let mut matcher = |_: usize, _: &Packet, _: &DecodedPacket| true;
        let matcher: &mut WorkflowResponseMatcher<'_> = &mut matcher;

        let error = transaction
            .execute(&sender, Some(matcher), None, &mut |_| Ok(()))
            .expect_err("a workflow cannot tell that its reply was the refused frame");

        let message = error.to_string();
        assert!(
            message.contains("request 0") && message.contains("exchange.unsolicited_limit"),
            "{message}"
        );
        assert_eq!(state.shutdowns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn early_stop_cancels_unsent_requests_without_incoherent_events_or_stats() {
        let (transaction, sender, state) =
            fixture_transaction(false, 2, crate::exchange::DEFAULT_MAX_RESPONSES);
        let mut matcher = |_: usize, _: &Packet, _: &DecodedPacket| true;
        let matcher: &mut WorkflowResponseMatcher<'_> = &mut matcher;
        let mut stop = |_: usize, _: &Packet, _: &DecodedPacket| true;
        let stop: &mut WorkflowStopPredicate<'_> = &mut stop;
        let mut collector = crate::exchange::Observed::default();

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
