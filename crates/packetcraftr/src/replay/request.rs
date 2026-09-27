// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Seek};
use std::time::Duration;

use packetcraftr_core::capture_file::{
    DEFAULT_MAX_STREAM_BYTES, DEFAULT_MAX_STREAM_FRAMES, Error as CaptureError, Reader,
};
use packetcraftr_core::filter::FrameSelector;
use packetcraftr_core::frame::{DEFAULT_MAX_SIZE, Frame};
use packetcraftr_netio::{deadline::MAX_WAIT, link::Mode as LinkMode};
use serde::{Deserialize, Serialize};

use super::error::Error;
use super::routing::Routing;
use crate::route::Interface;

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
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_source_frames: DEFAULT_MAX_STREAM_FRAMES,
            max_transmitted_bytes: DEFAULT_MAX_STREAM_BYTES,
            max_frame_bytes: DEFAULT_MAX_SIZE,
            max_duration: MAX_WAIT,
        }
    }
}

impl Limits {
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
        if self.max_duration.is_zero() || self.max_duration > MAX_WAIT {
            return Err(Error::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_WAIT,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Options {
    pub repeat: u32,
    pub inter_pass_delay: Duration,
    pub link_mode: LinkMode,
    pub timing: Timing,
    pub limits: Limits,
    /// Second explicit opt-in required in addition to policy approval.
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

type Rewind<R> = fn(&mut Reader<R>) -> Result<(), CaptureError>;

pub struct Source<R> {
    pub(super) reader: Reader<R>,
    pub(super) rewind: Option<Rewind<R>>,
}

impl<R: Read> Source<R> {
    #[must_use]
    pub fn stream(reader: Reader<R>) -> Self {
        Self {
            reader,
            rewind: None,
        }
    }
}

impl<R: Read + Seek> Source<R> {
    #[must_use]
    pub fn seekable(reader: Reader<R>) -> Self {
        Self {
            reader,
            rewind: Some(Reader::rewind),
        }
    }
}

impl<R> Source<R> {
    pub fn reader(&self) -> &Reader<R> {
        &self.reader
    }
}

pub(super) trait Selector {
    fn select(&mut self, source_index: u64, frame: &Frame) -> Result<bool, Error>;
    fn interface(&mut self, source_index: u64, frame: &Frame) -> Result<Interface, Error>;
}

impl<T: Selector + ?Sized> Selector for &mut T {
    fn select(&mut self, source_index: u64, frame: &Frame) -> Result<bool, Error> {
        (**self).select(source_index, frame)
    }

    fn interface(&mut self, source_index: u64, frame: &Frame) -> Result<Interface, Error> {
        (**self).interface(source_index, frame)
    }
}

pub(super) struct Selection {
    filter: Option<FrameSelector>,
    routing: Routing,
}

impl Selector for Selection {
    fn select(&mut self, source_index: u64, frame: &Frame) -> Result<bool, Error> {
        let Some(filter) = &self.filter else {
            return Ok(true);
        };
        filter
            .keep(source_index.saturating_add(1), frame)
            .map_err(|source| Error::Selection {
                source_index,
                source,
            })
    }

    fn interface(&mut self, source_index: u64, frame: &Frame) -> Result<Interface, Error> {
        self.routing.interface(source_index, frame)
    }
}

pub struct Request<R> {
    pub source: Source<R>,
    pub filter: Option<FrameSelector>,
    pub routing: Routing,
    pub options: Options,
}

impl<R> Request<R> {
    #[must_use]
    pub fn new(source: Source<R>, routing: Routing, options: Options) -> Self {
        Self {
            source,
            filter: None,
            routing,
            options,
        }
    }

    #[must_use]
    pub fn with_filter(mut self, filter: FrameSelector) -> Self {
        self.filter = Some(filter);
        self
    }

    pub fn validate(&self) -> Result<(), Error> {
        validate(&self.source, &self.options)
    }

    pub(super) fn into_parts(self) -> Parts<R, Selection> {
        Parts {
            source: self.source,
            selector: Selection {
                filter: self.filter,
                routing: self.routing,
            },
            options: self.options,
        }
    }
}

pub(super) struct Parts<R, S> {
    pub(super) source: Source<R>,
    pub(super) selector: S,
    pub(super) options: Options,
}

pub(super) fn validate<R>(source: &Source<R>, options: &Options) -> Result<(), Error> {
    options.validate()?;
    if options.repeat != 1 && source.rewind.is_none() {
        return Err(Error::InvalidLimit {
            field: "repeat",
            value: u64::from(options.repeat),
            reason: "repetition requires a stable seekable capture source",
        });
    }
    Ok(())
}
