// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Maximum cumulative intentional delay accepted by one replay operation.
use std::time::{Duration, SystemTime};

use packetcraftr_analysis::pcap::{
    DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, Format, Interface,
};
use packetcraftr_network::{
    Error as LiveIoError, interface::Id as InterfaceId, link::Mode as LinkMode,
    transmit::Report as IoSendReport,
};
use packetcraftr_packet::frame::Frame;
use serde::{Deserialize, Serialize};

use super::error::ReplayError;

pub const MAX_REPLAY_DURATION: Duration = packetcraftr_network::capture::MAX_TIMEOUT;

/// Timing policy used when replaying captured frames.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ReplayTiming {
    /// Preserve intervals between selected capture timestamps.
    Original,
    /// Multiply selected capture intervals by the positive finite factor.
    Scaled(f64),
    /// Replay selected frames at the positive finite frames-per-second rate.
    FixedRate(f64),
    /// Schedule every selected frame without an inter-frame delay.
    Immediate,
}

impl ReplayTiming {
    /// Validates any numeric timing parameter before frames are read.
    pub fn validate(self) -> Result<Self, ReplayError> {
        match self {
            Self::Scaled(value) if !value.is_finite() || value <= 0.0 => {
                Err(ReplayError::InvalidTiming {
                    mode: "scaled",
                    value,
                })
            }
            Self::FixedRate(value) if !value.is_finite() || value <= 0.0 => {
                Err(ReplayError::InvalidTiming {
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
        nonmonotonic_timestamps: NonmonotonicTimestampPolicy,
    ) -> Result<(Duration, Option<TimestampAdjustment>), ReplayError> {
        self.validate()?;
        match self {
            Self::Original => {
                let (previous, current) =
                    required_times(previous, current, source_index, "original")?;
                interval(
                    previous,
                    current,
                    source_index,
                    "original",
                    nonmonotonic_timestamps,
                )
            }
            Self::Scaled(factor) => {
                let (previous, current) =
                    required_times(previous, current, source_index, "scaled")?;
                let (original, adjustment) = interval(
                    previous,
                    current,
                    source_index,
                    "scaled",
                    nonmonotonic_timestamps,
                )?;
                let delay =
                    Duration::try_from_secs_f64(original.as_secs_f64() * factor).map_err(|_| {
                        ReplayError::InvalidTiming {
                            mode: "scaled",
                            value: factor,
                        }
                    })?;
                if !original.is_zero() && delay.is_zero() {
                    return Err(ReplayError::InvalidTiming {
                        mode: "scaled",
                        value: factor,
                    });
                }
                Ok((delay, adjustment))
            }
            Self::FixedRate(rate) => {
                let delay = Duration::try_from_secs_f64(1.0 / rate).map_err(|_| {
                    ReplayError::InvalidTiming {
                        mode: "fixed_rate",
                        value: rate,
                    }
                })?;
                if delay.is_zero() {
                    return Err(ReplayError::InvalidTiming {
                        mode: "fixed_rate",
                        value: rate,
                    });
                }
                Ok((delay, None))
            }
            Self::Immediate => Ok((Duration::ZERO, None)),
        }
    }

    pub(super) const fn requires_capture_timestamp(self) -> bool {
        matches!(self, Self::Original | Self::Scaled(_))
    }

    pub(super) const fn mode_name(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Scaled(_) => "scaled",
            Self::FixedRate(_) => "fixed_rate",
            Self::Immediate => "immediate",
        }
    }
}

fn required_times(
    previous: Option<SystemTime>,
    current: Option<SystemTime>,
    source_index: u64,
    mode: &'static str,
) -> Result<(SystemTime, SystemTime), ReplayError> {
    let unavailable = || ReplayError::TimestampUnavailable { source_index, mode };
    Ok((
        previous.ok_or_else(unavailable)?,
        current.ok_or_else(unavailable)?,
    ))
}

fn interval(
    previous: SystemTime,
    current: SystemTime,
    source_index: u64,
    mode: &'static str,
    policy: NonmonotonicTimestampPolicy,
) -> Result<(Duration, Option<TimestampAdjustment>), ReplayError> {
    match current.duration_since(previous) {
        Ok(delay) => Ok((delay, None)),
        Err(error) => {
            let backward_by = error.duration();
            match policy {
                NonmonotonicTimestampPolicy::Reject => Err(ReplayError::NonmonotonicTimestamp {
                    source_index,
                    mode,
                    backward_by,
                }),
                NonmonotonicTimestampPolicy::Clamp => Ok((
                    Duration::ZERO,
                    Some(TimestampAdjustment::NonmonotonicClamped { backward_by }),
                )),
            }
        }
    }
}

/// Policy for a selected frame whose timestamp precedes the prior selected frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum NonmonotonicTimestampPolicy {
    /// Fail before authorizing, delaying, or transmitting the affected frame.
    #[default]
    Reject,
    /// Schedule no delay and emit a typed adjustment report with the frame.
    Clamp,
}

/// Typed report emitted when replay timing explicitly adjusts capture time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TimestampAdjustment {
    NonmonotonicClamped { backward_by: Duration },
}

/// Finite resource ceilings applied before authorizing or transmitting a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayLimits {
    pub max_frames: u64,
    pub max_bytes: u64,
    pub max_frame_bytes: usize,
    pub max_duration: Duration,
}

impl Default for ReplayLimits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_STREAM_FRAMES,
            max_bytes: DEFAULT_STREAM_BYTES,
            max_frame_bytes: DEFAULT_SIZE_LIMIT,
            max_duration: MAX_REPLAY_DURATION,
        }
    }
}

impl ReplayLimits {
    pub fn validate(self) -> Result<Self, ReplayError> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("max_frame_bytes", self.max_frame_bytes as u64),
        ] {
            if value == 0 {
                return Err(ReplayError::InvalidLimit {
                    field,
                    value,
                    reason: "must be non-zero",
                });
            }
        }
        if self.max_frame_bytes as u64 > self.max_bytes {
            return Err(ReplayError::InvalidLimit {
                field: "max_frame_bytes",
                value: self.max_frame_bytes as u64,
                reason: "cannot exceed max_bytes",
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_REPLAY_DURATION {
            return Err(ReplayError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_REPLAY_DURATION,
            });
        }
        Ok(self)
    }
}

/// Complete replay request after the caller has selected an interface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayOptions {
    pub interface: InterfaceId,
    pub link_mode: LinkMode,
    pub timing: ReplayTiming,
    pub nonmonotonic_timestamps: NonmonotonicTimestampPolicy,
    pub limits: ReplayLimits,
}

/// Per-frame evidence emitted only after exact transmission is confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayFrameEvidence {
    /// Zero-based position in the source capture.
    pub source_index: u64,
    pub source_interface_id: Option<u32>,
    pub capture_interface: Interface,
    pub link_mode: LinkMode,
    pub scheduled_delay: Duration,
    pub timestamp_adjustment: Option<TimestampAdjustment>,
    pub frame: Frame,
    pub(super) transmission: ReplayTransmission,
}

impl ReplayFrameEvidence {
    pub fn transmission(&self) -> &ReplayTransmission {
        &self.transmission
    }
}

/// Terminal counters for a completed replay stream.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplaySummary {
    pub source_format: Format,
    pub timing: ReplayTiming,
    pub nonmonotonic_timestamps: NonmonotonicTimestampPolicy,
    pub frames_attempted: u64,
    pub frames_completed: u64,
    pub bytes_completed: u64,
    pub scheduled_duration: Duration,
    pub timestamp_adjustments: u64,
}

/// Prospective totals for the frame being authorized. They include only frames
/// that reach the wire; skipped frames charge read-side budgets, not policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayAuthorizationContext {
    pub packets: u64,
    pub wire_bytes: u64,
}

/// Selects a one-based capture-frame ordinal before byte accounting, authorization, delay,
/// or transmission.
///
/// Skipped frames consume the read-side frame budget only; they affect neither
/// policy totals nor timing. Selected frames retain capture spacing.
pub trait ReplaySelector {
    /// Decides whether this frame proceeds to authorization and transmission.
    fn select(&mut self, source_ordinal: u64, frame: &Frame) -> Result<bool, crate::BoundaryError>;
}

/// Explicit policy seam invoked before delay or transmission.
pub trait ReplayAuthorizer {
    fn authorize_operation(
        &mut self,
        context: ReplayAuthorizationContext,
        frame: &Frame,
        mode: LinkMode,
    ) -> Result<(), crate::BoundaryError>;
}

/// Exact-frame transmitter seam used by native and injected adapters.
pub trait ReplayTransmitter {
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
    ) -> Result<ReplayTransmission, LiveIoError>;
}

/// Exact provider report plus the concrete interface selected for a send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayTransmission {
    pub interface: InterfaceId,
    pub report: IoSendReport,
}
