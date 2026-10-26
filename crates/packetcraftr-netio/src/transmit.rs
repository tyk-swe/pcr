// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(native_layer3)]
pub(crate) mod raw_ip;

use bytes::Bytes;
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
            monotonic: Instant::now(),
            wall_clock: SystemTime::now(),
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
}

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
}
