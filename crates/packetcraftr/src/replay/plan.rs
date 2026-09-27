// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Each selected frame's place in the replay schedule and budget, decided
//! before the frame is authorized or sent.

use std::time::{Duration, SystemTime};

use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_netio::{interface::Id as InterfaceId, link::Mode as LinkMode};

use super::error::Error;
use super::request::{Options, Timing};

/// The running totals of one replay, which every frame's plan extends.
#[derive(Default)]
pub(super) struct Tally {
    pub(super) frames_read: u64,
    pub(super) frames_transmitted: u64,
    pub(super) bytes_transmitted: u64,
    pub(super) scheduled_duration: Duration,
    pub(super) pause_duration: Duration,
    pub(super) passes_completed: u32,
    pub(super) interfaces_used: Vec<InterfaceId>,
    pub(super) previous_timestamp: Option<SystemTime>,
    pub(super) has_previous: bool,
}

impl Tally {
    /// Commits a transmitted frame's plan to the totals.
    pub(super) fn complete(&mut self, plan: &FramePlan, timestamp: Option<SystemTime>) {
        self.frames_transmitted = plan.next_completed;
        self.bytes_transmitted = plan.next_bytes;
        self.scheduled_duration = plan.next_duration;
        self.previous_timestamp = timestamp;
        self.has_previous = true;
    }

    /// Records an interface a frame was transmitted on, once.
    pub(super) fn used(&mut self, interface: &InterfaceId) {
        if !self.interfaces_used.contains(interface) {
            self.interfaces_used.push(interface.clone());
        }
    }
}

/// One selected frame's link mode, delay, and the totals it would reach.
pub(super) struct FramePlan {
    pub(super) mode: LinkMode,
    pub(super) delay: Duration,
    pub(super) next_completed: u64,
    pub(super) next_bytes: u64,
    pub(super) next_duration: Duration,
}

/// Plans `frame` against the totals so far, failing before authorization
/// when it would cross a byte or duration limit.
pub(super) fn plan_frame(
    options: &Options,
    tally: &Tally,
    frame: &Frame,
    source_index: u64,
) -> Result<FramePlan, Error> {
    let limits = &options.limits;
    let next_bytes = tally
        .bytes_transmitted
        .checked_add(u64::from(frame.captured_length()))
        .ok_or(Error::TransmittedByteLimit {
            source_index,
            actual: u64::MAX,
            limit: limits.max_transmitted_bytes,
        })?;
    if next_bytes > limits.max_transmitted_bytes {
        return Err(Error::TransmittedByteLimit {
            source_index,
            actual: next_bytes,
            limit: limits.max_transmitted_bytes,
        });
    }
    let mode = link_mode(source_index, frame.link_type, options.link_mode)?;
    let delay = scheduled_delay(options.timing, tally, frame, source_index)?;
    let next_duration =
        tally
            .scheduled_duration
            .checked_add(delay)
            .ok_or(Error::DurationLimit {
                source_index,
                actual: Duration::MAX,
                limit: limits.max_duration,
            })?;
    if next_duration > limits.max_duration {
        return Err(Error::DurationLimit {
            source_index,
            actual: next_duration,
            limit: limits.max_duration,
        });
    }
    let next_completed =
        tally
            .frames_transmitted
            .checked_add(1)
            .ok_or(Error::SourceFrameLimit {
                source_index,
                actual: u64::MAX,
                limit: limits.max_source_frames,
            })?;
    Ok(FramePlan {
        mode,
        delay,
        next_completed,
        next_bytes,
        next_duration,
    })
}

fn scheduled_delay(
    timing: Timing,
    tally: &Tally,
    frame: &Frame,
    source_index: u64,
) -> Result<Duration, Error> {
    if !tally.has_previous {
        return Ok(Duration::ZERO);
    }
    match timing.delay_between(
        tally.previous_timestamp,
        frame.timestamp,
        source_index,
        tally.bytes_transmitted,
        tally
            .scheduled_duration
            .saturating_sub(tally.pause_duration),
    ) {
        Ok(delay) => Ok(delay),
        Err(Error::InvalidTiming { mode, value }) => Err(Error::Timing {
            source_index,
            mode,
            value,
        }),
        Err(error) => Err(error),
    }
}

impl Timing {
    /// The delay before the frame captured at `current`, after the frame
    /// captured at `previous`, once `transmitted_bytes` have been sent on a
    /// schedule of `scheduled_duration`.
    pub(super) fn delay_between(
        self,
        previous: Option<SystemTime>,
        current: Option<SystemTime>,
        source_index: u64,
        transmitted_bytes: u64,
        scheduled_duration: Duration,
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
            Self::BitRate(rate) => {
                // u64 bytes * eight bits * one billion nanoseconds fits u128.
                // Round the cumulative target, rather than each frame's gap,
                // so fractional nanoseconds do not accumulate scheduling drift.
                let nanos =
                    (u128::from(transmitted_bytes) * 8 * 1_000_000_000).div_ceil(u128::from(rate));
                let seconds =
                    u64::try_from(nanos / 1_000_000_000).map_err(|_| Error::InvalidTiming {
                        mode: "bit_rate",
                        value: rate as f64,
                    })?;
                let fraction = (nanos % 1_000_000_000) as u32;
                Ok(Duration::new(seconds, fraction).saturating_sub(scheduled_duration))
            }
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

/// The link mode a captured link type replays in: Ethernet through Layer 2,
/// raw IP through Layer 3. An explicit request must agree.
pub(super) fn link_mode(
    source_index: u64,
    link_type: LinkType,
    requested: LinkMode,
) -> Result<LinkMode, Error> {
    let supported = match link_type {
        LinkType::ETHERNET => LinkMode::Layer2,
        link_type if link_type.is_raw_ip() => LinkMode::Layer3,
        _ => {
            return Err(Error::UnsupportedLinkType {
                source_index,
                link_type: link_type.0,
            });
        }
    };
    match requested {
        LinkMode::Auto => Ok(supported),
        requested if requested == supported => Ok(requested),
        requested => Err(Error::LinkModeMismatch {
            source_index,
            link_type: link_type.0,
            requested,
        }),
    }
}
