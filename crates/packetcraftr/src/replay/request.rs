// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Seek};
use std::time::Duration;

use packetcraftr_core::capture_file::{
    DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, Error as CaptureError, Reader,
};
use packetcraftr_core::frame::{DEFAULT_SIZE_LIMIT, Frame};
use packetcraftr_netio::{
    capture::MAX_TIMEOUT, interface::Id as InterfaceId, link::Mode as LinkMode,
};
use serde::{Deserialize, Serialize};

use super::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum Timing {
    Original,
    Scaled(f64),
    FixedRate(f64),
    /// Positive bits per second, counting exact submitted frame bytes without
    /// synthetic media overhead. The first selected frame is immediate.
    BitRate(u64),
    Immediate,
}

impl Timing {
    /// Validates any numeric timing parameter before frames are read.
    pub fn validate(&self) -> Result<(), Error> {
        match *self {
            Self::BitRate(0) => Err(Error::InvalidTiming {
                mode: "bit_rate",
                value: 0.0,
            }),
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
}

/// Engine limits enforced independently of authorization. `max_source_frames`
/// counts all frames read, including skipped frames; `max_transmitted_bytes`
/// counts only bytes sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_source_frames: u64,
    pub max_transmitted_bytes: u64,
    pub max_frame_bytes: usize,
    /// Deadline on elapsed time from the replay's start, at most
    /// [`MAX_TIMEOUT`]. The intentional delays it schedules must also fit.
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_source_frames: DEFAULT_STREAM_FRAMES,
            max_transmitted_bytes: DEFAULT_STREAM_BYTES,
            max_frame_bytes: DEFAULT_SIZE_LIMIT,
            max_duration: MAX_TIMEOUT,
        }
    }
}

impl Limits {
    /// Applies the policy's transmission ceiling to frames read, including
    /// skipped frames.
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
        if self.max_duration.is_zero() || self.max_duration > MAX_TIMEOUT {
            return Err(Error::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_TIMEOUT,
            });
        }
        Ok(())
    }
}

/// How every selected frame of a replay is scheduled, bounded, and sent.
/// These settings do not depend on the capture, so a caller can validate them
/// before it opens one.
#[derive(Clone, Debug, PartialEq)]
pub struct Options {
    /// Fallback when the selector supplies no per-frame interface.
    pub interface: Option<InterfaceId>,
    pub repeat: u32,
    pub inter_pass_delay: Duration,
    pub link_mode: LinkMode,
    pub timing: Timing,
    pub limits: Limits,
    /// Second explicit opt-in required in addition to policy approval.
    /// Replay rebuilds every captured frame permissively, so live replay
    /// needs it.
    pub allow_permissive_live: bool,
}

impl Options {
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        self.timing.validate()?;
        if self.repeat == 0 || self.repeat > 1024 {
            return Err(Error::InvalidLimit {
                field: "repeat",
                value: u64::from(self.repeat),
                reason: "must be within 1..=1024",
            });
        }
        if self
            .inter_pass_delay
            .checked_mul(self.repeat - 1)
            .is_none_or(|delay| delay > self.limits.max_duration)
        {
            return Err(Error::InvalidDuration {
                value: self.inter_pass_delay,
                maximum: self.limits.max_duration,
            });
        }
        Ok(())
    }
}

/// Rewinds a seekable capture to its first frame.
type Rewind<R> = fn(&mut Reader<R>) -> Result<(), CaptureError>;

/// The capture a replay reads. A streaming source is read once, front to
/// back; only a seekable source can be repeated, because each pass rewinds
/// it.
pub struct Source<R> {
    pub(super) reader: Reader<R>,
    pub(super) rewind: Option<Rewind<R>>,
}

impl<R: Read> Source<R> {
    /// A capture read once. A request over it must not repeat.
    #[must_use]
    pub fn stream(reader: Reader<R>) -> Self {
        Self {
            reader,
            rewind: None,
        }
    }
}

impl<R: Read + Seek> Source<R> {
    /// A stable capture, rewound before every pass. The caller owns its
    /// immutability between passes; the CLI supplies an anonymous validated
    /// snapshot.
    #[must_use]
    pub fn seekable(reader: Reader<R>) -> Self {
        Self {
            reader,
            rewind: Some(Reader::rewind),
        }
    }
}

impl<R> Source<R> {
    /// The capture's reader, for its format and interface metadata.
    pub fn reader(&self) -> &Reader<R> {
        &self.reader
    }
}

/// Selects a one-based capture frame before byte accounting, authorization, delay,
/// or transmission.
///
/// Skipped frames consume the read-side frame budget only; they affect neither
/// policy totals nor timing. Selected frames retain capture spacing.
pub trait Selector {
    /// Decides whether this frame proceeds to authorization and transmission.
    fn select(&mut self, number: u64, frame: &Frame) -> Result<bool, crate::BoundaryError>;
    /// Selects an output interface after filtering. None uses the explicit fallback.
    fn interface(
        &mut self,
        _number: u64,
        _frame: &Frame,
    ) -> Result<Option<InterfaceId>, crate::BoundaryError> {
        Ok(None)
    }
}

impl<T: Selector + ?Sized> Selector for &mut T {
    fn select(&mut self, number: u64, frame: &Frame) -> Result<bool, crate::BoundaryError> {
        (**self).select(number, frame)
    }

    fn interface(
        &mut self,
        number: u64,
        frame: &Frame,
    ) -> Result<Option<InterfaceId>, crate::BoundaryError> {
        (**self).interface(number, frame)
    }
}

/// Selects every frame and maps none, so each uses the fallback interface.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllFrames;

impl Selector for AllFrames {
    fn select(&mut self, _number: u64, _frame: &Frame) -> Result<bool, crate::BoundaryError> {
        Ok(true)
    }
}

/// One replay: the capture, the frames selected from it, and how they are
/// sent.
pub struct Request<R, S = AllFrames> {
    pub source: Source<R>,
    pub selector: S,
    pub options: Options,
}

impl<R> Request<R> {
    /// Replays every frame of `source` under `options`.
    #[must_use]
    pub fn new(source: Source<R>, options: Options) -> Self {
        Self {
            source,
            selector: AllFrames,
            options,
        }
    }
}

impl<R, S> Request<R, S> {
    /// Replays only the frames `selector` selects, on the interfaces it maps.
    #[must_use]
    pub fn with_selector<T: Selector>(self, selector: T) -> Request<R, T> {
        Request {
            source: self.source,
            selector,
            options: self.options,
        }
    }

    /// Validates the options, and that only a seekable source repeats,
    /// without reading the capture.
    ///
    /// # Errors
    ///
    /// Returns the first invalid bound.
    pub fn validate(&self) -> Result<(), Error> {
        self.options.validate()?;
        if self.options.repeat != 1 && self.source.rewind.is_none() {
            return Err(Error::InvalidLimit {
                field: "repeat",
                value: u64::from(self.options.repeat),
                reason: "repetition requires a stable seekable capture source",
            });
        }
        Ok(())
    }
}
