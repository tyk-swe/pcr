// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed Layer 2 and Layer 3 transmission contracts; callers own policy authorization.

use bytes::Bytes;
use std::time::{Instant, SystemTime};

use super::Error;
use super::link::Mode;
use super::route::MaterializedRoute;

pub(crate) use self::{
    Frame as TransmissionFrame, Layer2Sender as Layer2Io, Report as IoSendReport,
    Sender as PacketIo, SystemLayer2 as SystemLayer2Io,
};

/// Complete Layer 2 frame with a verified Layer 2 route.
#[derive(Clone, Copy, Debug)]
pub struct Layer2Frame<'a> {
    bytes: &'a Bytes,
    route: &'a MaterializedRoute,
}

impl<'a> Layer2Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: &'a MaterializedRoute) -> Result<Self, Error> {
        require_link_mode(route, Mode::Layer2)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> &'a MaterializedRoute {
        self.route
    }
}

/// Raw Layer 3 packet with a verified Layer 3 route.
#[derive(Clone, Copy, Debug)]
pub struct Layer3Frame<'a> {
    bytes: &'a Bytes,
    route: &'a MaterializedRoute,
}

impl<'a> Layer3Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: &'a MaterializedRoute) -> Result<Self, Error> {
        require_link_mode(route, Mode::Layer3)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> &'a MaterializedRoute {
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
    pub fn try_new(bytes: &'a Bytes, route: &'a MaterializedRoute) -> Result<Self, Error> {
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

    pub fn route(self) -> &'a MaterializedRoute {
        match self {
            Self::Layer2(frame) => frame.route(),
            Self::Layer3(frame) => frame.route(),
        }
    }
}

fn require_link_mode(route: &MaterializedRoute, expected: Mode) -> Result<(), Error> {
    let actual = route.plan.mode;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::TransmissionModeMismatch { expected, actual })
    }
}

/// Timing evidence returned by a transmission provider.
///
/// A provider may know an exact commit point. Native synchronous providers
/// generally know only the interval during which submission was in progress;
/// captures inside that interval are therefore not proven fresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingEvidence {
    /// The provider established an exact monotonic commit marker.
    Commit {
        monotonic: Instant,
        wall_clock: Option<SystemTime>,
    },
    /// The provider established only a bounded synchronous submission
    /// interval. `finished` is the first safe freshness point.
    SubmissionInterval {
        started: Instant,
        finished: Instant,
        wall_started: Option<SystemTime>,
        wall_finished: Option<SystemTime>,
    },
}

impl TimingEvidence {
    pub fn commit(monotonic: Instant, wall_clock: Option<SystemTime>) -> Self {
        Self::Commit {
            monotonic,
            wall_clock,
        }
    }

    pub fn submission_interval(
        started: Instant,
        finished: Instant,
        wall_started: Option<SystemTime>,
        wall_finished: Option<SystemTime>,
    ) -> Self {
        Self::SubmissionInterval {
            started,
            finished,
            wall_started,
            wall_finished,
        }
    }

    /// The first monotonic point at which freshness is proven.
    pub fn freshness_at(self) -> Instant {
        match self {
            Self::Commit { monotonic, .. } => monotonic,
            Self::SubmissionInterval { finished, .. } => finished,
        }
    }

    pub fn started_at(self) -> Instant {
        match self {
            Self::Commit { monotonic, .. } => monotonic,
            Self::SubmissionInterval { started, .. } => started,
        }
    }

    /// Wall-clock metadata is output-only and must not be used for freshness.
    pub fn output_wall_clock(self) -> Option<SystemTime> {
        match self {
            Self::Commit { wall_clock, .. } => wall_clock,
            Self::SubmissionInterval { wall_finished, .. } => wall_finished,
        }
    }

    pub fn wall_bounds(self) -> (Option<SystemTime>, Option<SystemTime>) {
        match self {
            Self::Commit { wall_clock, .. } => (wall_clock, wall_clock),
            Self::SubmissionInterval {
                wall_started,
                wall_finished,
                ..
            } => (wall_started, wall_finished),
        }
    }

    pub fn is_monotonic(self) -> bool {
        match self {
            Self::Commit { .. } => true,
            Self::SubmissionInterval {
                started, finished, ..
            } => finished >= started,
        }
    }

    pub fn has_ordered_wall_bounds(self) -> bool {
        let (started, finished) = self.wall_bounds();
        match (started, finished) {
            (Some(started), Some(finished)) => finished >= started,
            _ => true,
        }
    }
}

/// Provider-accepted bytes and timing evidence for one transmission.
///
/// Providers use this type to report what they accepted. The live layer still
/// validates it against the exact typed input before retaining send evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    bytes_sent: usize,
    wire_bytes: Bytes,
    timing: TimingEvidence,
}

impl Report {
    pub fn from_provider(bytes_sent: usize, wire_bytes: Bytes, timing: TimingEvidence) -> Self {
        Self {
            bytes_sent,
            wire_bytes,
            timing,
        }
    }

    pub fn accepted(wire_bytes: Bytes, timing: TimingEvidence) -> Self {
        Self::from_provider(wire_bytes.len(), wire_bytes, timing)
    }

    pub fn bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    pub fn wire_bytes(&self) -> &Bytes {
        &self.wire_bytes
    }

    pub fn timing(&self) -> TimingEvidence {
        self.timing
    }

    /// Validates that this provider result describes acceptance of the exact
    /// typed frame submitted at the boundary.
    pub fn validate_against(&self, expected: &Bytes) -> Result<TimingEvidence, Error> {
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
        if self.wire_bytes != *expected {
            return Err(Error::InvalidSendEvidence {
                message: "wire_bytes differ from the exact submitted packet".to_owned(),
            });
        }
        if !self.timing.is_monotonic() || !self.timing.has_ordered_wall_bounds() {
            return Err(Error::InvalidSendTiming {
                message: "provider timing bounds are not ordered".to_owned(),
            });
        }
        Ok(self.timing)
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
