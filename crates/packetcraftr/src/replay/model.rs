// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Maximum cumulative intentional delay accepted by one replay operation.
use std::time::{Duration, SystemTime};

use packetcraftr_core::analysis::pcap::{
    DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, Format, Interface,
};
use packetcraftr_core::frame::Frame;
use packetcraftr_netio::{
    Error as LiveIoError, interface::Id as InterfaceId, link::Mode as LinkMode,
    route::Materialized as MaterializedRoute, transmit::Report as IoSendReport,
};
use serde::{Deserialize, Serialize};

use super::error::Error;

pub const MAX_REPLAY_DURATION: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;

/// Timing policy used when replaying captured frames.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum Timing {
    Original,
    Scaled(f64),
    FixedRate(f64),
    Immediate,
}

impl Timing {
    /// Validates any numeric timing parameter before frames are read.
    pub fn validate(&self) -> Result<(), Error> {
        match *self {
            Self::Scaled(value) if !value.is_finite() || value <= 0.0 => {
                Err(Error::InvalidTiming {
                    mode: "scaled",
                    value,
                })
            }
            Self::FixedRate(value) if !value.is_finite() || value <= 0.0 => {
                Err(Error::InvalidTiming {
                    mode: "fixed_rate",
                    value,
                })
            }
            _ => Ok(()),
        }
    }

    pub(super) fn delay_between(
        self,
        previous: Option<SystemTime>,
        current: Option<SystemTime>,
        source_index: u64,
    ) -> Result<Duration, Error> {
        self.validate()?;
        match self {
            Self::Original => {
                let (previous, current) =
                    required_times(previous, current, source_index, "original")?;
                Ok(current.duration_since(previous).unwrap_or(Duration::ZERO))
            }
            Self::Scaled(factor) => {
                let (previous, current) =
                    required_times(previous, current, source_index, "scaled")?;
                let original = current.duration_since(previous).unwrap_or(Duration::ZERO);
                let delay =
                    Duration::try_from_secs_f64(original.as_secs_f64() * factor).map_err(|_| {
                        Error::InvalidTiming {
                            mode: "scaled",
                            value: factor,
                        }
                    })?;
                if !original.is_zero() && delay.is_zero() {
                    return Err(Error::InvalidTiming {
                        mode: "scaled",
                        value: factor,
                    });
                }
                Ok(delay)
            }
            Self::FixedRate(rate) => {
                let delay =
                    Duration::try_from_secs_f64(1.0 / rate).map_err(|_| Error::InvalidTiming {
                        mode: "fixed_rate",
                        value: rate,
                    })?;
                if delay.is_zero() {
                    return Err(Error::InvalidTiming {
                        mode: "fixed_rate",
                        value: rate,
                    });
                }
                Ok(delay)
            }
            Self::Immediate => Ok(Duration::ZERO),
        }
    }
}

fn required_times(
    previous: Option<SystemTime>,
    current: Option<SystemTime>,
    source_index: u64,
    mode: &'static str,
) -> Result<(SystemTime, SystemTime), Error> {
    match (previous, current) {
        (Some(previous), Some(current)) => Ok((previous, current)),
        _ => Err(Error::TimestampUnavailable { source_index, mode }),
    }
}

/// Finite resource ceilings applied before authorizing or transmitting a frame.
///
/// The two aggregate ceilings bound different quantities, and the names say
/// which: `max_source_frames` bounds frames *read* from the capture, including
/// the ones a selector skips before they are ever authorized, while
/// `max_transmitted_bytes` bounds only the bytes that actually reach the wire.
/// This engine bound is independent of the authorizer's own budget on purpose:
/// it is what still bounds the operation when an injected authorizer approves
/// everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_source_frames: u64,
    pub max_transmitted_bytes: u64,
    pub max_frame_bytes: usize,
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_source_frames: DEFAULT_STREAM_FRAMES,
            max_transmitted_bytes: DEFAULT_STREAM_BYTES,
            max_frame_bytes: DEFAULT_SIZE_LIMIT,
            max_duration: MAX_REPLAY_DURATION,
        }
    }
}

impl Limits {
    /// The engine ceilings a traffic policy's per-operation budget implies.
    ///
    /// The policy bounds what may be *transmitted*; this bound is applied to
    /// what is *read*, which is at least as many frames, so the operation
    /// cannot outlive the policy budget even when every frame is selected.
    #[must_use]
    pub fn from_policy(
        policy: &crate::policy::Policy,
        max_frame_bytes: usize,
        max_duration: Duration,
    ) -> Self {
        Self {
            max_source_frames: policy.max_packets_per_operation,
            max_transmitted_bytes: policy.max_bytes_per_operation,
            max_frame_bytes,
            max_duration,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        for (field, value) in [
            ("max_source_frames", self.max_source_frames),
            ("max_transmitted_bytes", self.max_transmitted_bytes),
            (
                "max_frame_bytes",
                u64::try_from(self.max_frame_bytes).unwrap_or(u64::MAX),
            ),
        ] {
            if value == 0 {
                return Err(Error::InvalidLimit {
                    field,
                    value,
                    reason: "must be non-zero",
                });
            }
        }
        if u64::try_from(self.max_frame_bytes).unwrap_or(u64::MAX) > self.max_transmitted_bytes {
            return Err(Error::InvalidLimit {
                field: "max_frame_bytes",
                value: u64::try_from(self.max_frame_bytes).unwrap_or(u64::MAX),
                reason: "cannot exceed max_transmitted_bytes",
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_REPLAY_DURATION {
            return Err(Error::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_REPLAY_DURATION,
            });
        }
        Ok(())
    }
}

/// Complete replay request after the caller has selected an interface.
#[derive(Clone, Debug, PartialEq)]
pub struct Options {
    pub interface: InterfaceId,
    pub link_mode: LinkMode,
    pub timing: Timing,
    pub limits: Limits,
}

/// Per-frame evidence emitted only after exact transmission is confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameEvidence {
    pub source_index: u64,
    pub source_interface_id: Option<u32>,
    pub capture_interface: Interface,
    pub link_mode: LinkMode,
    pub scheduled_delay: Duration,
    pub frame: Frame,
    pub(super) transmission: Transmission,
}

impl FrameEvidence {
    pub fn transmission(&self) -> &Transmission {
        &self.transmission
    }
}

/// Terminal counters for a completed replay stream.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Summary {
    pub source_format: Format,
    pub timing: Timing,
    #[serde(rename = "frames_attempted")]
    pub frames_read: u64,
    #[serde(rename = "frames_completed")]
    pub frames_transmitted: u64,
    #[serde(rename = "bytes_completed")]
    pub bytes_transmitted: u64,
    pub scheduled_duration: Duration,
}

/// Selects a one-based capture frame before byte accounting, authorization, delay,
/// or transmission.
///
/// Skipped frames consume the read-side frame budget only; they affect neither
/// policy totals nor timing. Selected frames retain capture spacing.
pub trait Selector {
    /// Decides whether this frame proceeds to authorization and transmission.
    fn select(&mut self, number: u64, frame: &Frame) -> Result<bool, crate::BoundaryError>;
}

/// Exact-frame transmitter seam used by native and injected adapters.
///
/// The two methods are one handoff: [`plan_frame`](Transmitter::plan_frame)
/// produces the exact route the engine then has authorized, and that same
/// route is handed back to [`transmit`](Transmitter::transmit). "The bytes on
/// the wire are routed by the plan that was authorized" is therefore
/// structural, not a runtime comparison of remembered frames.
pub trait Transmitter {
    /// Resolve and validate the concrete interface, then passively select and
    /// materialize the final route, before any intentional delay.
    fn plan_frame(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<MaterializedRoute, LiveIoError>;

    /// Transmit the exact frame through the route that was authorized.
    fn transmit(
        &mut self,
        route: &MaterializedRoute,
        frame: &Frame,
    ) -> Result<Transmission, LiveIoError>;
}

/// Exact provider report plus the concrete interface selected for a send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmission {
    pub interface: InterfaceId,
    pub report: IoSendReport,
}
