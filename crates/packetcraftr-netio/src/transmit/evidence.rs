// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Instant, SystemTime};

use bytes::Bytes;
use packetcraftr_core::clock::{Clock, SystemClock};
use packetcraftr_core::error::{Classification, Classified};

use crate::{Error, error::live_io_invariant};

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

    pub fn validate_exact(&self, expected: &Bytes) -> Result<(), Error> {
        if self.bytes_sent != expected.len() {
            return Err(Error::PartialSend {
                expected: expected.len(),
                actual: self.bytes_sent,
            });
        }
        if self.wire_bytes.len() != self.bytes_sent {
            return Err(Error::InvalidSendReport {
                bytes_sent: self.bytes_sent,
                wire_bytes: self.wire_bytes.len(),
            });
        }
        if self.wire_bytes.as_ref() != expected.as_ref() {
            return Err(Error::InvalidSendEvidence {
                fault: SendEvidenceFault::AcceptedBytesDiffer,
            });
        }
        if !self.timing.is_consistent() {
            return Err(Error::InvalidSendEvidence {
                fault: SendEvidenceFault::InconsistentTiming,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_validation_requires_submitted_bytes() {
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
    fn report_timestamps_are_consistent() {
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
