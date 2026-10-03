// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, SystemTime};

use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_netio::{interface::Id as InterfaceId, link::Mode as LinkMode};

use super::error::Error;
use super::request::{Options, Timing};

#[derive(Default)]
pub(super) struct Tally {
    pub(super) frames_read: u64,
    pub(super) frames_transmitted: u64,
    pub(super) bytes_transmitted: u64,
    pub(super) scheduled_duration: Duration,
    pub(super) pause_duration: Duration,
    /// Wall time that passed before the schedule's anchor. It counts against
    /// the duration limit but is not part of the schedule.
    pub(super) setup_duration: Duration,
    pub(super) passes_completed: u32,
    pub(super) interfaces_used: Vec<InterfaceId>,
    pub(super) previous_timestamp: Option<SystemTime>,
    pub(super) has_previous: bool,
}

impl Tally {
    pub(super) fn complete(&mut self, plan: &FramePlan, timestamp: Option<SystemTime>) {
        self.frames_transmitted = plan.next_completed;
        self.bytes_transmitted = plan.next_bytes;
        self.scheduled_duration = plan.next_duration;
        // Capture stamps can step backwards; the newest one stays the pacing
        // reference so the step is not paid again by the next frame.
        self.previous_timestamp = match (self.previous_timestamp, timestamp) {
            (Some(previous), Some(current)) => Some(previous.max(current)),
            (_, current) => current,
        };
        self.has_previous = true;
    }

    pub(super) fn used(&mut self, interface: &InterfaceId) {
        if !self.interfaces_used.contains(interface) {
            self.interfaces_used.push(interface.clone());
        }
    }
}

pub(super) struct FramePlan {
    pub(super) mode: LinkMode,
    pub(super) delay: Duration,
    pub(super) next_completed: u64,
    pub(super) next_bytes: u64,
    pub(super) next_duration: Duration,
}

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
    let delay = scheduled_delay(options, tally, frame, source_index)?;
    let next_duration =
        tally
            .scheduled_duration
            .checked_add(delay)
            .ok_or(Error::DurationLimit {
                source_index,
                actual: Duration::MAX,
                limit: limits.max_duration,
            })?;
    let wall_duration = next_duration.saturating_add(tally.setup_duration);
    if wall_duration > limits.max_duration {
        return Err(Error::DurationLimit {
            source_index,
            actual: wall_duration,
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
    options: &Options,
    tally: &Tally,
    frame: &Frame,
    source_index: u64,
) -> Result<Duration, Error> {
    if !tally.has_previous {
        return Ok(Duration::ZERO);
    }
    let timing = options.timing;
    let delay = timing.delay_between(
        tally.previous_timestamp,
        frame.timestamp,
        source_index,
        tally.bytes_transmitted,
        tally
            .scheduled_duration
            .saturating_sub(tally.pause_duration),
    )?;
    // Only captured gaps are clamped; rate-derived delays are never idle gaps.
    Ok(match (timing, options.max_gap) {
        (Timing::Original | Timing::Scaled(_), Some(max_gap)) => delay.min(max_gap),
        _ => delay,
    })
}

impl Timing {
    pub(super) fn delay_between(
        self,
        previous: Option<SystemTime>,
        current: Option<SystemTime>,
        source_index: u64,
        transmitted_bytes: u64,
        scheduled_duration: Duration,
    ) -> Result<Duration, Error> {
        let invalid = |value| Error::Timing {
            source_index,
            mode: self.mode(),
            value,
        };
        match self {
            Self::Original => {
                let (previous, current) =
                    required_times(previous, current, source_index, self.mode())?;
                Ok(current.duration_since(previous).unwrap_or(Duration::ZERO))
            }
            Self::Scaled(factor) => {
                let (previous, current) =
                    required_times(previous, current, source_index, self.mode())?;
                let original = current.duration_since(previous).unwrap_or(Duration::ZERO);
                let delay = Duration::try_from_secs_f64(original.as_secs_f64() * factor)
                    .map_err(|_| invalid(factor))?;
                if !original.is_zero() && delay.is_zero() {
                    return Err(invalid(factor));
                }
                Ok(delay)
            }
            Self::FixedRate(rate) => Self::fixed_rate_period(rate).ok_or_else(|| invalid(rate)),
            Self::Immediate => Ok(Duration::ZERO),
            Self::BitRate(rate) => {
                // u64 bytes * eight bits * one billion nanoseconds fits u128.
                // Round the cumulative target, rather than each frame's gap,
                // so fractional nanoseconds do not accumulate scheduling drift.
                let nanos =
                    (u128::from(transmitted_bytes) * 8 * 1_000_000_000).div_ceil(u128::from(rate));
                let seconds =
                    u64::try_from(nanos / 1_000_000_000).map_err(|_| invalid(rate as f64))?;
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

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::replay::request::Limits;

    fn delays(timing: Timing, stamps: &[Option<Duration>]) -> Result<Vec<Duration>, Error> {
        clamped_delays(timing, None, stamps)
    }

    fn clamped_delays(
        timing: Timing,
        max_gap: Option<Duration>,
        stamps: &[Option<Duration>],
    ) -> Result<Vec<Duration>, Error> {
        let options = Options {
            repeat: 1,
            inter_pass_delay: Duration::ZERO,
            link_mode: LinkMode::Auto,
            timing,
            max_gap,
            limits: Limits::default(),
            allow_permissive_live: false,
        };
        let mut tally = Tally::default();
        let mut delays = Vec::new();
        for (index, stamp) in stamps.iter().enumerate() {
            let frame = match stamp {
                Some(offset) => Frame::new(UNIX_EPOCH + *offset, LinkType::ETHERNET, vec![0; 14]),
                None => Frame::without_timestamp(LinkType::ETHERNET, vec![0; 14]),
            }
            .expect("capture frame");
            let plan = plan_frame(&options, &tally, &frame, index as u64)?;
            tally.complete(&plan, frame.timestamp);
            delays.push(plan.delay);
        }
        Ok(delays)
    }

    fn seconds(values: &[u64]) -> Vec<Option<Duration>> {
        values
            .iter()
            .map(|value| Some(Duration::from_secs(*value)))
            .collect()
    }

    #[test]
    fn a_maximum_gap_never_changes_rate_derived_delays() {
        for timing in [
            Timing::FixedRate(2.0),
            Timing::BitRate(112),
            Timing::Immediate,
        ] {
            let stamps = seconds(&[0, 1, 2]);
            assert_eq!(
                clamped_delays(timing, Some(Duration::from_millis(1)), &stamps).unwrap(),
                delays(timing, &stamps).unwrap(),
                "{timing:?}"
            );
        }
    }
}
