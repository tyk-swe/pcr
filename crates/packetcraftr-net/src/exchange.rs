// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Composition contracts for capture-before-send exchanges.

use super::Error;
use super::capture::{CaptureProvider, CaptureQueueLimits};
use super::route::PlannedRoute;
use super::transmit::{IoSendReport, PacketIo, TransmissionFrame};

/// Composes separately owned transmission and capture providers.
#[derive(Clone, Copy, Debug)]
pub struct Composite<S, C> {
    sender: S,
    capture: C,
}

impl<S, C> Composite<S, C> {
    pub fn new(sender: S, capture: C) -> Self {
        Self { sender, capture }
    }

    pub fn sender(&self) -> &S {
        &self.sender
    }

    pub fn capture(&self) -> &C {
        &self.capture
    }

    pub fn into_parts(self) -> (S, C) {
        (self.sender, self.capture)
    }
}

impl<S, C> PacketIo for Composite<S, C>
where
    S: PacketIo,
    C: Send + Sync,
{
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, Error> {
        self.sender.send(frame)
    }
}

impl<S, C> CaptureProvider for Composite<S, C>
where
    S: Send + Sync,
    C: CaptureProvider,
{
    type Capture = C::Capture;

    fn arm_capture(
        &self,
        route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, Error> {
        self.capture.arm_capture(route, limits)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use packetcraftr_capture::LinkType;

    use super::*;
    use crate::capture::{CaptureSession, CaptureStatistics, CapturedFrame};
    use crate::interface::Id as InterfaceId;
    use crate::link::{Capability as LinkCapability, Mode as LinkMode};
    use crate::route::{
        Decision as RouteDecision, Materialized as MaterializedRoute, Scope as DestinationScope,
        SelectionReason as RouteSelectionReason,
    };

    #[derive(Clone)]
    struct CountingSender {
        calls: Arc<AtomicUsize>,
    }

    impl PacketIo for CountingSender {
        fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(IoSendReport {
                bytes_sent: frame.bytes().len(),
                wire_bytes: frame.bytes().clone(),
            })
        }
    }

    struct EmptyCapture;

    impl CaptureSession for EmptyCapture {
        fn wait_ready(&mut self, _timeout: Duration) -> Result<(), Error> {
            Ok(())
        }

        fn next_captured_frame(
            &mut self,
            _timeout: Duration,
        ) -> Result<Option<CapturedFrame>, Error> {
            Ok(None)
        }

        fn shutdown(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn statistics(&self) -> CaptureStatistics {
            CaptureStatistics::default()
        }
    }

    #[derive(Clone)]
    struct CountingCaptureProvider {
        calls: Arc<AtomicUsize>,
    }

    impl CaptureProvider for CountingCaptureProvider {
        type Capture = EmptyCapture;

        fn arm_capture(
            &self,
            _route: &PlannedRoute,
            _limits: CaptureQueueLimits,
        ) -> Result<Self::Capture, Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(EmptyCapture)
        }
    }

    fn route() -> MaterializedRoute {
        MaterializedRoute {
            plan: PlannedRoute {
                route: RouteDecision {
                    interface: InterfaceId {
                        name: "test0".to_owned(),
                        index: 7,
                    },
                    source_mac: None,
                    selected_address: Some("192.0.2.1".parse().unwrap()),
                    preferred_source: None,
                    next_hop: None,
                    selection_reason: RouteSelectionReason::OnLink,
                    destination_scope: DestinationScope::Private,
                    mtu: 1_500,
                    capability: LinkCapability::Layer3,
                    link_type: LinkType::RAW,
                },
                mode: LinkMode::Layer3,
                lookup_destination: Some("192.0.2.2".parse().unwrap()),
                final_destination: Some("192.0.2.2".parse().unwrap()),
                visited_destinations: vec!["192.0.2.2".parse().unwrap()],
                packet_source: Some("192.0.2.1".parse().unwrap()),
                neighbor_source: None,
                neighbor_target: None,
                destination_mac: None,
                source_mac: None,
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            },
            neighbor_resolution: None,
        }
    }

    #[test]
    fn composite_exposes_parts_and_delegates_send_and_capture() {
        let send_calls = Arc::new(AtomicUsize::new(0));
        let capture_calls = Arc::new(AtomicUsize::new(0));
        let composite = Composite::new(
            CountingSender {
                calls: Arc::clone(&send_calls),
            },
            CountingCaptureProvider {
                calls: Arc::clone(&capture_calls),
            },
        );
        assert!(Arc::ptr_eq(&composite.sender().calls, &send_calls));
        assert!(Arc::ptr_eq(&composite.capture().calls, &capture_calls));

        let route = route();
        let bytes = Bytes::from_static(&[0x45, 0, 0, 20]);
        let frame = TransmissionFrame::try_new(&bytes, &route).unwrap();
        let report = composite.send(frame).unwrap();
        assert_eq!(report.bytes_sent, bytes.len());
        assert_eq!(report.wire_bytes, bytes);
        composite
            .arm_capture(&route.plan, CaptureQueueLimits::default())
            .unwrap();
        assert_eq!(send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(capture_calls.load(Ordering::SeqCst), 1);

        let (sender, capture) = composite.into_parts();
        assert!(Arc::ptr_eq(&sender.calls, &send_calls));
        assert!(Arc::ptr_eq(&capture.calls, &capture_calls));
    }
}
