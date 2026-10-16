// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Local quality of an interval with no correlated reply. None of these
/// values asserts that the remote endpoint or network caused the silence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// The capture remains active. A later qualification settles this value.
    Pending,
    Unknown,
    NoReportedLoss,
    Incomplete,
    /// A transport provider completed its own response timeout.
    TransportTimeout,
}

impl Coverage {
    pub const fn permits_silence(self) -> bool {
        matches!(self, Self::NoReportedLoss | Self::TransportTimeout)
    }
}

impl From<packetcraftr_netio::capture::ObservationQuality> for Coverage {
    fn from(quality: packetcraftr_netio::capture::ObservationQuality) -> Self {
        use packetcraftr_netio::capture::ObservationQuality;
        match quality {
            ObservationQuality::Unknown => Self::Unknown,
            ObservationQuality::NoReportedLoss => Self::NoReportedLoss,
            ObservationQuality::Incomplete => Self::Incomplete,
        }
    }
}

/// A response, qualified absence of a reply, or inability to observe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Measurement<R> {
    Response(R),
    NoReply(Coverage),
    Unavailable,
}

/// Final local acquisition quality for the published attempts in this inclusive
/// sequence interval and stage. Gaps are allowed; it applies only to existing
/// pending no-reply measurements. Final coverage and positive evidence are never
/// changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Qualification {
    stage: super::Stage,
    first_sequence: u64,
    last_sequence: u64,
    coverage: Coverage,
}

impl Qualification {
    pub fn new(
        stage: super::Stage,
        first_sequence: u64,
        last_sequence: u64,
        quality: packetcraftr_netio::capture::ObservationQuality,
    ) -> Option<Self> {
        (first_sequence <= last_sequence).then(|| Self {
            stage,
            first_sequence,
            last_sequence,
            coverage: quality.into(),
        })
    }

    pub const fn stage(self) -> super::Stage {
        self.stage
    }
    pub const fn first_sequence(self) -> u64 {
        self.first_sequence
    }
    pub const fn last_sequence(self) -> u64 {
        self.last_sequence
    }

    pub const fn coverage(self) -> Coverage {
        self.coverage
    }
}
