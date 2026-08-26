// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed Layer 2 and Layer 3 transmission contracts; callers own policy authorization.

use bytes::Bytes;
use std::time::{Instant, SystemTime};

use super::Error;
use super::link::Mode;
use super::route::Materialized;

/// Complete Layer 2 frame with a verified Layer 2 route.
#[derive(Clone, Copy, Debug)]
pub struct Layer2Frame<'a> {
    bytes: &'a Bytes,
    route: &'a Materialized,
}

impl<'a> Layer2Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: &'a Materialized) -> Result<Self, Error> {
        require_link_mode(route, Mode::Layer2)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> &'a Materialized {
        self.route
    }
}

/// Raw Layer 3 packet with a verified Layer 3 route.
#[derive(Clone, Copy, Debug)]
pub struct Layer3Frame<'a> {
    bytes: &'a Bytes,
    route: &'a Materialized,
}

impl<'a> Layer3Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: &'a Materialized) -> Result<Self, Error> {
        require_link_mode(route, Mode::Layer3)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> &'a Materialized {
        self.route
    }
}

/// Mode-tagged transmission input used by the high-level client.
#[derive(Clone, Copy, Debug)]
pub enum Frame<'a> {
    Layer2(Layer2Frame<'a>),
    Layer3(Layer3Frame<'a>),
}

impl<'a> Frame<'a> {
    /// Selects the typed provider boundary from the already-materialized route.
    pub fn try_new(bytes: &'a Bytes, route: &'a Materialized) -> Result<Self, Error> {
        match route.plan.mode {
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

    pub fn route(self) -> &'a Materialized {
        match self {
            Self::Layer2(frame) => frame.route(),
            Self::Layer3(frame) => frame.route(),
        }
    }
}

fn require_link_mode(route: &Materialized, expected: Mode) -> Result<(), Error> {
    let actual = route.plan.mode;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::TransmissionModeMismatch { expected, actual })
    }
}

/// A monotonic/wall-clock observation captured as one provider event.
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

/// Provider-established transmission timing.
///
/// An exact marker identifies the provider's successful commit event. A
/// submission interval means only that acceptance occurred after `started`
/// and no later than `completed`; captures inside that interval are not proven
/// to be post-send.
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

    /// Earliest marker after which a capture is proven to follow acceptance.
    pub fn freshness_marker(self) -> TimeMarker {
        self.completed
    }

    /// Whether monotonic endpoints describe a valid interval or exact event.
    pub fn is_consistent(self) -> bool {
        self.started.monotonic <= self.completed.monotonic
            && (!self.exact || self.started.monotonic == self.completed.monotonic)
    }
}

/// In-progress injected-provider submission.
///
/// Providers that lack an exact commit event create this immediately before
/// entering their send operation and complete it only after success. Clock
/// endpoints cannot be supplied independently by callers.
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
    /// Records an exact successful provider commit at the call site.
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

    /// Validates count, exact accepted bytes, and provider monotonic timing for
    /// one submitted frame.
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
                message: "provider-accepted bytes differ from the exact submitted frame".to_owned(),
            });
        }
        if !self.timing.is_consistent() {
            return Err(super::Error::InvalidSendEvidence {
                message: "provider timing has inconsistent monotonic endpoints".to_owned(),
            });
        }
        Ok(())
    }
}

/// Unified packet-I/O seam used by the root client and injected providers.
pub trait Sender: Send + Sync {
    fn send(&self, frame: Frame<'_>) -> Result<Report, Error>;
}

/// Native or injected Layer 2 transmission implementation.
pub trait Layer2Sender: Send + Sync {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<Report, Error>;
}

/// Target-selected native Layer 2 provider; requires `native-layer2`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLayer2;

impl Layer2Sender for SystemLayer2 {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<Report, Error> {
        super::platform::system_send_layer2(frame)
    }
}

/// Native or injected raw Layer 3 transmission implementation.
pub trait Layer3Sender: Send + Sync {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<Report, Error>;
}

/// Target-selected native Layer 3 provider; requires `native-layer3`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLayer3;

impl Layer3Sender for SystemLayer3 {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<Report, Error> {
        super::platform::system_send_layer3(frame)
    }
}

/// Composes independently owned Layer 2 and Layer 3 providers into [`Sender`].
#[derive(Clone, Copy, Debug)]
pub struct Dispatch<L2, L3> {
    layer2: L2,
    layer3: L3,
}

impl<L2, L3> Dispatch<L2, L3> {
    pub fn new(layer2: L2, layer3: L3) -> Self {
        Self { layer2, layer3 }
    }
}

impl<L2, L3> Sender for Dispatch<L2, L3>
where
    L2: Layer2Sender,
    L3: Layer3Sender,
{
    fn send(&self, frame: Frame<'_>) -> Result<Report, Error> {
        match frame {
            Frame::Layer2(frame) => self.layer2.send_layer2(frame),
            Frame::Layer3(frame) => self.layer3.send_layer3(frame),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn backward_wall_clock_step_does_not_invalidate_submission_timing() {
        let expected = Bytes::from_static(&[1, 2, 3]);
        let started_monotonic = Instant::now();
        let report = Report {
            bytes_sent: expected.len(),
            wire_bytes: expected.clone(),
            timing: Timing {
                started: TimeMarker {
                    monotonic: started_monotonic,
                    wall_clock: SystemTime::UNIX_EPOCH + Duration::from_secs(2),
                },
                completed: TimeMarker {
                    monotonic: started_monotonic + Duration::from_millis(1),
                    wall_clock: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                },
                exact: false,
            },
        };

        assert!(report.validate_exact(&expected).is_ok());
    }

    #[test]
    fn inconsistent_monotonic_intervals_and_nonexact_commit_markers_fail_closed() {
        let expected = Bytes::from_static(&[1, 2, 3]);
        let first = Instant::now();
        for timing in [
            Timing {
                started: TimeMarker {
                    monotonic: first + Duration::from_millis(1),
                    wall_clock: SystemTime::UNIX_EPOCH,
                },
                completed: TimeMarker {
                    monotonic: first,
                    wall_clock: SystemTime::UNIX_EPOCH,
                },
                exact: false,
            },
            Timing {
                started: TimeMarker {
                    monotonic: first,
                    wall_clock: SystemTime::UNIX_EPOCH,
                },
                completed: TimeMarker {
                    monotonic: first + Duration::from_millis(1),
                    wall_clock: SystemTime::UNIX_EPOCH,
                },
                exact: true,
            },
        ] {
            let report = Report {
                bytes_sent: expected.len(),
                wire_bytes: expected.clone(),
                timing,
            };

            assert!(!report.timing().is_consistent());
            assert!(matches!(
                report.validate_exact(&expected),
                Err(Error::InvalidSendEvidence { ref message })
                    if message.contains("timing")
            ));
        }
    }
}
