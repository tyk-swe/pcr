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
    transmit::Report as IoSendReport,
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
    pub fn validate(self) -> Result<Self, Error> {
        match self {
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
            timing => Ok(timing),
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_frames: u64,
    pub max_bytes: u64,
    pub max_frame_bytes: usize,
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_STREAM_FRAMES,
            max_bytes: DEFAULT_STREAM_BYTES,
            max_frame_bytes: DEFAULT_SIZE_LIMIT,
            max_duration: MAX_REPLAY_DURATION,
        }
    }
}

impl Limits {
    pub fn validate(self) -> Result<Self, Error> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
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
        if u64::try_from(self.max_frame_bytes).unwrap_or(u64::MAX) > self.max_bytes {
            return Err(Error::InvalidLimit {
                field: "max_frame_bytes",
                value: u64::try_from(self.max_frame_bytes).unwrap_or(u64::MAX),
                reason: "cannot exceed max_bytes",
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_REPLAY_DURATION {
            return Err(Error::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_REPLAY_DURATION,
            });
        }
        Ok(self)
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

/// Prospective totals for the frame being authorized. They include only frames
/// that reach the wire; skipped frames charge read-side budgets, not policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationContext {
    pub packets: u64,
    pub wire_bytes: u64,
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

/// Explicit policy seam invoked before delay or transmission.
pub trait Authorizer {
    fn authorize_operation(
        &mut self,
        context: AuthorizationContext,
        frame: &Frame,
        mode: LinkMode,
    ) -> Result<(), crate::BoundaryError>;
}

/// Exact-frame transmitter seam used by native and injected adapters.
pub trait Transmitter {
    /// Resolve and validate the concrete interface before any intentional delay.
    fn validate_interface(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<InterfaceId, LiveIoError>;

    fn transmit(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<Transmission, LiveIoError>;
}

/// Exact provider report plus the concrete interface selected for a send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmission {
    pub interface: InterfaceId,
    pub report: IoSendReport,
}
