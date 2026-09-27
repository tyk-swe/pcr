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

/// Captures inside a submission interval are not proven to be post-send.
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
    use std::time::Duration;

    use super::*;
    use crate::error::test_support::assert_same_failure;

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
            assert_same_failure(
                &report
                    .validate_exact(&expected)
                    .expect_err("inconsistent provider timing is refused"),
                &Error::InvalidSendEvidence {
                    fault: SendEvidenceFault::InconsistentTiming,
                },
            );
        }
    }
}
