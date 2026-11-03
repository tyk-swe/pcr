// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(native_layer3)]
pub(crate) mod raw_ip;
#[cfg(any(test, all(target_os = "linux", pcap_backend)))]
pub(crate) mod session;

use bytes::Bytes;
use packetcraftr_core::clock::{Clock, SystemClock};
use std::net::IpAddr;
use std::time::{Instant, SystemTime};

use packetcraftr_core::error::{Classification, Classified};

use super::Error;
use super::error::live_io_invariant;
use super::link::Mode;
use super::route::Decision;

/// Which exact-transmission invariant a provider's wire evidence violated.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendEvidenceFault {
    #[error("provider-accepted bytes differ from the exact submitted frame")]
    AcceptedBytesDiffer,
    #[error("provider timing has inconsistent monotonic endpoints")]
    InconsistentTiming,
    #[error("provider-accepted bytes cannot form a capture record")]
    UnrepresentableFrame(#[from] packetcraftr_core::frame::Error),
}

impl Classified for SendEvidenceFault {
    fn classification(&self) -> Classification {
        live_io_invariant()
    }
}

/// The route facts a transmission backend checks before sending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route<'a> {
    pub decision: &'a Decision,
    pub mode: Mode,
    /// Destination the route was looked up for; absent for destination-free Layer 2 frames.
    pub lookup_destination: Option<IpAddr>,
}

#[derive(Clone, Copy, Debug)]
pub struct Layer2Frame<'a> {
    bytes: &'a Bytes,
    route: Route<'a>,
}

impl<'a> Layer2Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: Route<'a>) -> Result<Self, Error> {
        require_link_mode(route, Mode::Layer2)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> Route<'a> {
        self.route
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Layer3Frame<'a> {
    bytes: &'a Bytes,
    route: Route<'a>,
}

impl<'a> Layer3Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: Route<'a>) -> Result<Self, Error> {
        require_link_mode(route, Mode::Layer3)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> Route<'a> {
        self.route
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Outbound<'a> {
    Layer2(Layer2Frame<'a>),
    Layer3(Layer3Frame<'a>),
}

impl<'a> Outbound<'a> {
    pub fn try_new(bytes: &'a Bytes, route: Route<'a>) -> Result<Self, Error> {
        match route.mode {
            Mode::Layer2 => Layer2Frame::try_new(bytes, route).map(Self::Layer2),
            Mode::Layer3 => Layer3Frame::try_new(bytes, route).map(Self::Layer3),
            Mode::Auto => Err(Error::UnresolvedLinkMode),
        }
    }

    pub fn bytes(self) -> &'a Bytes {
        match self {
            Self::Layer2(frame) => frame.bytes(),
            Self::Layer3(frame) => frame.bytes(),
        }
    }

    pub fn route(self) -> Route<'a> {
        match self {
            Self::Layer2(frame) => frame.route(),
            Self::Layer3(frame) => frame.route(),
        }
    }
}

fn require_link_mode(route: Route<'_>, expected: Mode) -> Result<(), Error> {
    let actual = route.mode;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::TransmissionModeMismatch { expected, actual })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeMarker {
    monotonic: Instant,
    wall_clock: SystemTime,
}

impl TimeMarker {
    fn now() -> Self {
        Self {
            monotonic: SystemClock.now(),
            wall_clock: SystemClock.wall_now(),
        }
    }

    pub fn monotonic(self) -> Instant {
        self.monotonic
    }

    pub fn wall_clock(self) -> SystemTime {
        self.wall_clock
    }
}

/// The interval during which a provider successfully submitted the exact bytes.
///
/// A matching reply can arrive before submission returns. Its eligibility
/// starts at entry to the successful operation, not at return; neither marker
/// claims an exact wire departure time or authenticates a responder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    started: TimeMarker,
    completed: TimeMarker,
    exact: bool,
}

impl Timing {
    pub fn started(self) -> TimeMarker {
        self.started
    }

    /// Earliest capture eligible for correlation with this successful submission.
    ///
    /// Protocol identity and integrity checks still decide whether a capture
    /// matches. Captures before this marker, or without monotonic ingress
    /// timing, cannot be attributed to this submission.
    pub fn freshness_marker(self) -> TimeMarker {
        self.started
    }

    /// When the provider returned successful acceptance of the exact bytes.
    pub fn completed(self) -> TimeMarker {
        self.completed
    }

    pub fn is_consistent(self) -> bool {
        self.started.monotonic <= self.completed.monotonic
            && (!self.exact || self.started.monotonic == self.completed.monotonic)
    }
}

/// Created immediately before entering a send operation and completed only after success.
#[derive(Debug)]
pub struct Submission {
    started: TimeMarker,
}

impl Submission {
    pub fn start() -> Self {
        Self {
            started: TimeMarker::now(),
        }
    }

    pub fn started(&self) -> TimeMarker {
        self.started
    }

    pub fn complete(self, bytes_sent: usize, wire_bytes: Bytes) -> Report {
        Report {
            bytes_sent,
            wire_bytes,
            timing: Timing {
                started: self.started,
                completed: TimeMarker::now(),
                exact: false,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    bytes_sent: usize,
    wire_bytes: Bytes,
    timing: Timing,
}

impl Report {
    pub fn committed(bytes_sent: usize, wire_bytes: Bytes) -> Self {
        let committed = TimeMarker::now();
        Self {
            bytes_sent,
            wire_bytes,
            timing: Timing {
                started: committed,
                completed: committed,
                exact: true,
            },
        }
    }

    pub fn bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    pub fn wire_bytes(&self) -> &Bytes {
        &self.wire_bytes
    }

    pub fn timing(&self) -> Timing {
        self.timing
    }

    pub fn validate_exact(&self, expected: &Bytes) -> Result<(), super::Error> {
        if self.bytes_sent != expected.len() {
            return Err(super::Error::PartialSend {
                expected: expected.len(),
                actual: self.bytes_sent,
            });
        }
        if self.wire_bytes.len() != self.bytes_sent {
            return Err(super::Error::InvalidSendReport {
                bytes_sent: self.bytes_sent,
                wire_bytes: self.wire_bytes.len(),
            });
        }
        if self.wire_bytes.as_ref() != expected.as_ref() {
            return Err(super::Error::InvalidSendEvidence {
                fault: SendEvidenceFault::AcceptedBytesDiffer,
            });
        }
        if !self.timing.is_consistent() {
            return Err(super::Error::InvalidSendEvidence {
                fault: SendEvidenceFault::InconsistentTiming,
            });
        }
        Ok(())
    }
}

pub trait Provider: Send + Sync {
    fn send(&self, outbound: Outbound<'_>) -> Result<Report, Error>;

    /// Creates an operation-scoped provider without sending or opening a transmission handle.
    /// Existing providers default to one-shot sends.
    fn session(&self) -> Box<dyn Provider + '_> {
        Box::new(DirectProvider(self))
    }
}

struct DirectProvider<'a, P: ?Sized>(&'a P);

impl<P: Provider + ?Sized> Provider for DirectProvider<'_, P> {
    fn send(&self, outbound: Outbound<'_>) -> Result<Report, Error> {
        self.0.send(outbound)
    }

    fn session(&self) -> Box<dyn Provider + '_> {
        Box::new(DirectProvider(self.0))
    }
}

/// The native one-shot transmission provider.
///
/// On Linux with libpcap, a session can retain one compatible handle. Concurrent
/// session sends are rejected, and incompatible interfaces use one-shot dispatch.
/// Sends are rejected if the session's network namespace changes or cannot be
/// verified. A failed native submission invalidates the handle and its error is
/// returned for later compatible sends. Dropping the session closes the handle.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    fn send(&self, outbound: Outbound<'_>) -> Result<Report, Error> {
        match outbound {
            Outbound::Layer2(frame) => {
                // A renamed, removed, or recreated interface must not receive the frame.
                #[cfg(native_layer2)]
                super::platform::verify_interface_identity(&frame.route().decision.interface)?;
                super::platform::send_layer2(frame)
            }
            Outbound::Layer3(packet) => {
                #[cfg(native_layer3)]
                super::platform::verify_interface_identity(&packet.route().decision.interface)?;
                super::platform::send_layer3(packet)
            }
        }
    }

    #[cfg(all(target_os = "linux", pcap_backend))]
    fn session(&self) -> Box<dyn Provider + '_> {
        Box::new(session::Bounded::new(super::platform::transmit_backend()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        interface::Id as InterfaceId,
        link::Capability,
        route::{Scope, SelectionReason},
    };
    use packetcraftr_core::frame::LinkType;

    fn decision() -> Decision {
        Decision {
            interface: InterfaceId {
                name: "test0".to_owned(),
                index: 1,
            },
            source_mac: None,
            selected_source: None,
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Link,
            mtu: 1500,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        }
    }

    fn route<'a>(decision: &'a Decision, mode: Mode) -> Route<'a> {
        Route {
            decision,
            mode,
            lookup_destination: None,
        }
    }

    #[test]
    fn frames_require_their_exact_link_mode() {
        let decision = decision();
        let bytes = Bytes::from_static(b"frame");
        assert!(Layer2Frame::try_new(&bytes, route(&decision, Mode::Layer2)).is_ok());
        assert!(matches!(
            Layer2Frame::try_new(&bytes, route(&decision, Mode::Layer3)),
            Err(Error::TransmissionModeMismatch {
                expected: Mode::Layer2,
                actual: Mode::Layer3
            })
        ));
        assert!(matches!(
            Layer2Frame::try_new(&bytes, route(&decision, Mode::Auto)),
            Err(Error::TransmissionModeMismatch {
                expected: Mode::Layer2,
                actual: Mode::Auto
            })
        ));
        assert!(matches!(
            Layer3Frame::try_new(&bytes, route(&decision, Mode::Auto)),
            Err(Error::TransmissionModeMismatch {
                expected: Mode::Layer3,
                actual: Mode::Auto
            })
        ));
        assert!(Layer3Frame::try_new(&bytes, route(&decision, Mode::Layer3)).is_ok());
        assert!(matches!(
            Layer3Frame::try_new(&bytes, route(&decision, Mode::Layer2)),
            Err(Error::TransmissionModeMismatch {
                expected: Mode::Layer3,
                actual: Mode::Layer2
            })
        ));
    }

    #[test]
    fn outbound_dispatches_on_resolved_mode_and_rejects_auto() {
        let decision = decision();
        let bytes = Bytes::from_static(b"frame");
        assert!(matches!(
            Outbound::try_new(&bytes, route(&decision, Mode::Layer2)),
            Ok(Outbound::Layer2(_))
        ));
        assert!(matches!(
            Outbound::try_new(&bytes, route(&decision, Mode::Layer3)),
            Ok(Outbound::Layer3(_))
        ));
        assert!(matches!(
            Outbound::try_new(&bytes, route(&decision, Mode::Auto)),
            Err(Error::UnresolvedLinkMode)
        ));
    }

    #[test]
    fn validate_exact_accepts_only_the_exact_submitted_bytes() {
        let expected = Bytes::from_static(b"exact");
        assert!(
            Report::committed(expected.len(), expected.clone())
                .validate_exact(&expected)
                .is_ok()
        );
        assert!(matches!(
            Report::committed(expected.len() - 1, expected.clone()).validate_exact(&expected),
            Err(Error::PartialSend {
                expected: 5,
                actual: 4
            })
        ));
        assert!(matches!(
            Report::committed(expected.len() + 1, expected.clone()).validate_exact(&expected),
            Err(Error::PartialSend {
                expected: 5,
                actual: 6
            })
        ));
        assert!(matches!(
            Report::committed(expected.len(), Bytes::from_static(b"exac"))
                .validate_exact(&expected),
            Err(Error::InvalidSendReport {
                bytes_sent: 5,
                wire_bytes: 4
            })
        ));
        let earlier = TimeMarker::now();
        let later = TimeMarker {
            monotonic: earlier.monotonic + std::time::Duration::from_secs(1),
            wall_clock: earlier.wall_clock,
        };
        let mistimed = Report {
            bytes_sent: expected.len(),
            wire_bytes: expected.clone(),
            timing: Timing {
                started: later,
                completed: earlier,
                exact: false,
            },
        };
        assert!(matches!(
            mistimed.validate_exact(&expected),
            Err(Error::InvalidSendEvidence {
                fault: SendEvidenceFault::InconsistentTiming
            })
        ));
        assert!(matches!(
            Report::committed(expected.len(), Bytes::from_static(b"EXACT"))
                .validate_exact(&expected),
            Err(Error::InvalidSendEvidence {
                fault: SendEvidenceFault::AcceptedBytesDiffer
            })
        ));
    }

    #[test]
    fn accessors_return_the_exact_submitted_frame_and_counts() {
        let decision = decision();
        let bytes = Bytes::from_static(b"frame");
        let frame = Layer2Frame::try_new(&bytes, route(&decision, Mode::Layer2)).unwrap();
        assert_eq!(frame.bytes(), &bytes);
        let frame = Layer3Frame::try_new(&bytes, route(&decision, Mode::Layer3)).unwrap();
        assert_eq!(frame.bytes(), &bytes);
        let outbound = Outbound::try_new(&bytes, route(&decision, Mode::Layer3)).unwrap();
        assert_eq!(outbound.bytes(), &bytes);
        assert_eq!(outbound.route().mode, Mode::Layer3);
        let report = Report::committed(5, bytes.clone());
        assert_eq!(report.bytes_sent(), 5);
        assert_eq!(report.wire_bytes(), &bytes);
    }

    #[test]
    fn inconsistent_timing_is_rejected() {
        let earlier = TimeMarker::now();
        let later = TimeMarker {
            monotonic: earlier.monotonic + std::time::Duration::from_secs(1),
            wall_clock: earlier.wall_clock,
        };
        let reversed = Timing {
            started: later,
            completed: earlier,
            exact: false,
        };
        assert!(!reversed.is_consistent());
        let inexact = Timing {
            started: earlier,
            completed: later,
            exact: true,
        };
        assert!(!inexact.is_consistent());
        let ordered = Timing {
            started: earlier,
            completed: later,
            exact: false,
        };
        assert!(ordered.is_consistent());
    }

    #[test]
    fn committed_and_completed_reports_have_consistent_timing() {
        let report = Report::committed(3, Bytes::from_static(b"abc"));
        assert!(report.timing().is_consistent());
        assert_eq!(
            report.timing().started().monotonic(),
            report.timing().completed().monotonic()
        );
        let report = Submission::start().complete(3, Bytes::from_static(b"abc"));
        assert!(report.timing().is_consistent());
        assert!(report.timing().started().monotonic() <= report.timing().completed().monotonic());
    }

    #[derive(Default)]
    struct Counts {
        opens: std::sync::atomic::AtomicUsize,
        sends: std::sync::atomic::AtomicUsize,
        fallbacks: std::sync::atomic::AtomicUsize,
        drops: std::sync::atomic::AtomicUsize,
        namespace: std::sync::atomic::AtomicUsize,
        generation: std::sync::atomic::AtomicUsize,
        fail_open: std::sync::atomic::AtomicBool,
        partial_send: std::sync::atomic::AtomicBool,
        pause: Option<std::sync::Arc<(std::sync::Barrier, std::sync::Barrier)>>,
    }

    struct TestResource {
        counts: std::sync::Arc<Counts>,
        generation: usize,
    }

    impl Drop for TestResource {
        fn drop(&mut self) {
            self.counts
                .drops
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct TestBackend(std::sync::Arc<Counts>, usize);

    impl TestBackend {
        fn new(counts: std::sync::Arc<Counts>) -> Self {
            let namespace = counts.namespace.load(std::sync::atomic::Ordering::SeqCst);
            Self(counts, namespace)
        }
    }

    impl session::Backend for TestBackend {
        type Key = (InterfaceId, usize, Option<IpAddr>);
        type Resource = TestResource;

        fn key(&self, outbound: Outbound<'_>) -> Result<Option<Self::Key>, Error> {
            if self.0.namespace.load(std::sync::atomic::Ordering::SeqCst) != self.1 {
                return Err(Error::Send {
                    message: "network namespace changed".to_owned(),
                    source: None,
                });
            }
            if matches!(outbound, Outbound::Layer3(_)) {
                return Ok(None);
            }
            let route = outbound.route();
            Ok(Some((
                route.decision.interface.clone(),
                self.0.namespace.load(std::sync::atomic::Ordering::SeqCst),
                route.lookup_destination,
            )))
        }

        fn open(&self, _: Outbound<'_>) -> Result<Option<Self::Resource>, Error> {
            self.0
                .opens
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.0.fail_open.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Error::Send {
                    message: "open failed".to_owned(),
                    source: None,
                });
            }
            Ok(Some(TestResource {
                counts: self.0.clone(),
                generation: self.0.generation.load(std::sync::atomic::Ordering::SeqCst),
            }))
        }

        fn send(
            &self,
            resource: &mut Self::Resource,
            outbound: Outbound<'_>,
        ) -> Result<Report, Error> {
            self.0
                .sends
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(pause) = &self.0.pause {
                pause.0.wait();
                pause.1.wait();
            }
            if resource.generation != self.0.generation.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Error::Send {
                    message: "device removed".to_owned(),
                    source: None,
                });
            }
            if self
                .0
                .partial_send
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(Error::PartialSend {
                    expected: outbound.bytes().len(),
                    actual: 2,
                });
            }
            Ok(Report::committed(
                outbound.bytes().len(),
                outbound.bytes().clone(),
            ))
        }

        fn fallback(&self, outbound: Outbound<'_>) -> Result<Report, Error> {
            self.0
                .fallbacks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Report::committed(
                outbound.bytes().len(),
                outbound.bytes().clone(),
            ))
        }
    }

    #[test]
    fn operation_session_reuses_one_resource_and_stops_after_device_loss() {
        use std::sync::atomic::Ordering::SeqCst;
        let counts = std::sync::Arc::new(Counts::default());
        let session = session::Bounded::new(TestBackend::new(counts.clone()));
        let decision = decision();
        let bytes = Bytes::from_static(b"packet bytes");
        let original = Outbound::try_new(&bytes, route(&decision, Mode::Layer2)).unwrap();
        for _ in 0..8 {
            session
                .send(original)
                .unwrap()
                .validate_exact(&bytes)
                .unwrap();
        }
        assert_eq!(counts.opens.load(SeqCst), 1);
        assert_eq!(counts.sends.load(SeqCst), 8);

        let mut other = decision.clone();
        other.interface.index += 1;
        let other_interface = Outbound::try_new(&bytes, route(&other, Mode::Layer2)).unwrap();
        session
            .send(other_interface)
            .unwrap()
            .validate_exact(&bytes)
            .unwrap();
        counts.namespace.store(1, SeqCst);
        assert!(session.send(original).is_err());
        let layer3 = Outbound::try_new(&bytes, route(&decision, Mode::Layer3)).unwrap();
        assert!(session.send(layer3).is_err());
        counts.namespace.store(0, SeqCst);
        session
            .send(layer3)
            .unwrap()
            .validate_exact(&bytes)
            .unwrap();
        for destination in ["192.0.2.1", "2001:db8::1"] {
            let mut other_family = route(&decision, Mode::Layer2);
            other_family.lookup_destination = Some(destination.parse().unwrap());
            let outbound = Outbound::try_new(&bytes, other_family).unwrap();
            session
                .send(outbound)
                .unwrap()
                .validate_exact(&bytes)
                .unwrap();
        }
        assert_eq!(counts.fallbacks.load(SeqCst), 4);
        assert_eq!(counts.opens.load(SeqCst), 1);

        counts.generation.store(1, SeqCst);
        assert!(session.send(original).is_err());
        assert_eq!(counts.drops.load(SeqCst), 1);
        assert!(session.send(original).is_err());
        assert_eq!(counts.sends.load(SeqCst), 9);
        drop(session);
        assert_eq!(counts.drops.load(SeqCst), 1);
    }

    #[test]
    fn failed_session_initialization_does_not_leave_a_resource() {
        use std::sync::atomic::Ordering::SeqCst;
        let counts = std::sync::Arc::new(Counts::default());
        counts.fail_open.store(true, SeqCst);
        let session = session::Bounded::new(TestBackend::new(counts.clone()));
        let decision = decision();
        let bytes = Bytes::from_static(b"packet");
        let outbound = Outbound::try_new(&bytes, route(&decision, Mode::Layer2)).unwrap();
        assert!(session.send(outbound).is_err());
        assert_eq!(counts.sends.load(SeqCst), 0);
        counts.fail_open.store(false, SeqCst);
        session.send(outbound).unwrap();
        drop(session);
        assert_eq!(counts.opens.load(SeqCst), 2);
        assert_eq!(counts.drops.load(SeqCst), 1);
    }

    #[test]
    fn session_preserves_partial_send_evidence_without_retrying() {
        use packetcraftr_core::error::{Classified, Code};
        use std::sync::atomic::Ordering::SeqCst;
        let counts = std::sync::Arc::new(Counts::default());
        counts.partial_send.store(true, SeqCst);
        let session = session::Bounded::new(TestBackend::new(counts.clone()));
        let decision = decision();
        let bytes = Bytes::from_static(b"packet");
        let outbound = Outbound::try_new(&bytes, route(&decision, Mode::Layer2)).unwrap();
        for _ in 0..2 {
            let error = session.send(outbound).unwrap_err();
            assert!(matches!(
                error,
                Error::PartialSend {
                    expected: 6,
                    actual: 2
                }
            ));
            assert_eq!(error.classification().code, Code::IoPartialSend);
        }
        assert_eq!(counts.sends.load(SeqCst), 1);
        assert_eq!(counts.drops.load(SeqCst), 1);
    }

    #[test]
    fn session_rejects_concurrent_sends_without_opening_another_resource() {
        use std::sync::atomic::Ordering::SeqCst;
        let barriers =
            std::sync::Arc::new((std::sync::Barrier::new(2), std::sync::Barrier::new(2)));
        let counts = std::sync::Arc::new(Counts {
            pause: Some(barriers.clone()),
            ..Counts::default()
        });
        let session = session::Bounded::new(TestBackend::new(counts.clone()));
        let decision = decision();
        let bytes = Bytes::from_static(b"packet");
        let outbound = Outbound::try_new(&bytes, route(&decision, Mode::Layer2)).unwrap();
        std::thread::scope(|scope| {
            let first = scope.spawn(|| session.send(outbound));
            barriers.0.wait();
            assert!(session.send(outbound).is_err());
            barriers.1.wait();
            first.join().unwrap().unwrap();
        });
        assert_eq!(counts.opens.load(SeqCst), 1);
        assert_eq!(counts.sends.load(SeqCst), 1);
    }
}
