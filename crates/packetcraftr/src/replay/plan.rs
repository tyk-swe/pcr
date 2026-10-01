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

    fn millis(values: &[u64]) -> Vec<Option<Duration>> {
        values
            .iter()
            .map(|value| Some(Duration::from_millis(*value)))
            .collect()
    }

    #[test]
    fn a_maximum_gap_clamps_only_the_gaps_that_exceed_it() {
        let stamps = millis(&[0, 10, 610_010, 610_030]);
        let gap = Some(Duration::from_millis(50));
        assert_eq!(
            clamped_delays(Timing::Original, gap, &stamps).unwrap(),
            [
                Duration::ZERO,
                Duration::from_millis(10),
                Duration::from_millis(50),
                Duration::from_millis(20),
            ]
        );
        assert_eq!(
            clamped_delays(Timing::Original, gap, &stamps).unwrap()[1],
            delays(Timing::Original, &stamps).unwrap()[1],
            "a shorter gap is untouched"
        );
    }

    #[test]
    fn a_scaled_gap_is_clamped_after_scaling() {
        let stamps = millis(&[0, 100, 100_100]);
        let gap = Some(Duration::from_millis(30));
        assert_eq!(
            clamped_delays(Timing::Scaled(0.5), gap, &stamps).unwrap(),
            [
                Duration::ZERO,
                Duration::from_millis(30),
                Duration::from_millis(30),
            ],
            "50ms scaled exceeds the clamp"
        );
        assert_eq!(
            clamped_delays(Timing::Scaled(0.2), gap, &stamps).unwrap(),
            [
                Duration::ZERO,
                Duration::from_millis(20),
                Duration::from_millis(30),
            ],
            "20ms scaled stays below the clamp"
        );
    }

    #[test]
    fn a_maximum_gap_lowers_the_planned_duration_under_the_duration_limit() {
        let stamps = seconds(&[0, 600]);
        let frame = |offset: &Option<Duration>| {
            Frame::new(
                UNIX_EPOCH + offset.unwrap(),
                LinkType::ETHERNET,
                vec![0; 14],
            )
            .expect("capture frame")
        };
        let plan = |max_gap| {
            let options = Options {
                repeat: 1,
                inter_pass_delay: Duration::ZERO,
                link_mode: LinkMode::Auto,
                timing: Timing::Original,
                max_gap,
                limits: Limits {
                    max_duration: Duration::from_secs(60),
                    ..Limits::default()
                },
                allow_permissive_live: false,
            };
            let mut tally = Tally::default();
            let first = frame(&stamps[0]);
            let planned = plan_frame(&options, &tally, &first, 0).unwrap();
            tally.complete(&planned, first.timestamp);
            plan_frame(&options, &tally, &frame(&stamps[1]), 1)
        };

        assert!(
            matches!(
                plan(None),
                Err(Error::DurationLimit {
                    source_index: 1,
                    ..
                })
            ),
            "the unclamped idle gap exceeds the limit"
        );
        assert_eq!(
            plan(Some(Duration::from_secs(5))).unwrap().next_duration,
            Duration::from_secs(5)
        );
        assert!(matches!(
            plan(Some(Duration::from_secs(61))),
            Err(Error::DurationLimit {
                source_index: 1,
                ..
            })
        ));
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

    #[test]
    fn a_backward_capture_step_is_not_paid_again_by_the_next_frame() {
        let stamps = seconds(&[10, 9, 11]);
        assert_eq!(
            delays(Timing::Original, &stamps).unwrap(),
            [Duration::ZERO, Duration::ZERO, Duration::from_secs(1)]
        );
        assert_eq!(
            delays(Timing::Scaled(2.0), &stamps).unwrap(),
            [Duration::ZERO, Duration::ZERO, Duration::from_secs(2)]
        );
    }

    #[test]
    fn interleaved_capture_clocks_add_only_the_forward_progress() {
        let stamps = millis(&[10_000, 9_000, 10_100, 9_100, 10_200, 9_200]);
        assert_eq!(
            delays(Timing::Original, &stamps).unwrap(),
            [
                Duration::ZERO,
                Duration::ZERO,
                Duration::from_millis(100),
                Duration::ZERO,
                Duration::from_millis(100),
                Duration::ZERO,
            ]
        );
    }

    #[test]
    fn forward_capture_stamps_keep_their_spacing() {
        let stamps = millis(&[1_000, 1_250, 1_250, 2_000]);
        assert_eq!(
            delays(Timing::Original, &stamps).unwrap(),
            [
                Duration::ZERO,
                Duration::from_millis(250),
                Duration::ZERO,
                Duration::from_millis(750),
            ]
        );
        assert_eq!(
            delays(Timing::Scaled(0.5), &stamps).unwrap(),
            [
                Duration::ZERO,
                Duration::from_millis(125),
                Duration::ZERO,
                Duration::from_millis(375),
            ]
        );
    }

    #[test]
    fn a_frame_without_a_capture_timestamp_cannot_be_paced_from_capture_time() {
        for (timing, mode) in [
            (Timing::Original, "original"),
            (Timing::Scaled(2.0), "scaled"),
        ] {
            let mut stamps = seconds(&[10, 9]);
            stamps.push(None);
            assert!(
                matches!(
                    delays(timing, &stamps),
                    Err(Error::TimestampUnavailable {
                        source_index: 2,
                        mode: found
                    }) if found == mode
                ),
                "{mode}"
            );
        }
    }

    #[test]
    fn an_unrepresentable_scaled_delay_fails_at_the_frame_that_needs_it() {
        for factor in [f64::MAX, 1e-300] {
            let error = delays(Timing::Scaled(factor), &seconds(&[1, 2])).expect_err("scaled");
            assert!(
                matches!(
                    error,
                    Error::Timing { source_index: 1, mode: "scaled", value } if value == factor
                ),
                "{factor}: {error:?}"
            );
        }
    }

    #[test]
    fn a_bit_rate_target_beyond_the_duration_range_fails_with_the_source_index() {
        let options = Options {
            repeat: 1,
            inter_pass_delay: Duration::ZERO,
            link_mode: LinkMode::Auto,
            timing: Timing::BitRate(1),
            max_gap: None,
            limits: Limits {
                max_transmitted_bytes: u64::MAX,
                ..Limits::default()
            },
            allow_permissive_live: false,
        };
        let tally = Tally {
            bytes_transmitted: u64::MAX / 2,
            has_previous: true,
            ..Tally::default()
        };
        let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![0; 14]).expect("capture frame");
        let error = plan_frame(&options, &tally, &frame, 4)
            .map(|plan| plan.delay)
            .expect_err("the cumulative target overflows Duration");
        assert!(
            matches!(
                error,
                Error::Timing {
                    source_index: 4,
                    mode: "bit_rate",
                    value: 1.0
                }
            ),
            "{error:?}"
        );
    }
}
