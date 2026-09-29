// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use super::Errors;

pub(crate) const MAX_RATE: u32 = 1_000_000;

pub(crate) fn check_limits<E>(
    ranges: &[(&'static str, usize, usize)],
    bounded_by: &[(&'static str, usize, usize, &str)],
    invalid: impl Fn(&'static str, u64, String) -> E,
) -> Result<(), E> {
    for &(field, value, maximum) in ranges {
        if value == 0 || value > maximum {
            return Err(invalid(
                field,
                widen(value),
                format!("must be within 1..={maximum}"),
            ));
        }
    }
    for &(field, value, maximum, reason) in bounded_by {
        if value > maximum {
            return Err(invalid(field, widen(value), reason.to_owned()));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EvidenceLimits {
    pub(crate) max_frames: usize,
    pub(crate) max_bytes: usize,
    pub(crate) max_undecoded: usize,
}

impl EvidenceLimits {
    pub(crate) fn validate<E>(
        &self,
        invalid: impl Fn(&'static str, u64, String) -> E,
    ) -> Result<(), E> {
        check_limits(
            &[
                (
                    "max_evidence_frames",
                    self.max_frames,
                    packetcraftr_netio::capture::MAX_CAPTURE_QUEUE_FRAMES,
                ),
                (
                    "max_evidence_bytes",
                    self.max_bytes,
                    packetcraftr_netio::capture::MAX_CAPTURE_QUEUE_BYTES,
                ),
            ],
            &[(
                "max_undecoded",
                self.max_undecoded,
                self.max_frames,
                "cannot exceed max_evidence_frames",
            )],
            invalid,
        )
    }
}

pub(crate) fn check_rate<R: Errors>(
    errors: &R,
    field: &'static str,
    rate: Option<u32>,
) -> Result<(), R::Error> {
    match rate {
        Some(rate) if rate == 0 || rate > MAX_RATE => Err(errors.invalid_limit(
            field,
            u64::from(rate),
            format!("must be within 1..={MAX_RATE}"),
        )),
        _ => Ok(()),
    }
}

pub(crate) fn duration_violation(value: Duration, maximum: Duration) -> bool {
    value.is_zero() || value > maximum
}

fn widen(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use packetcraftr_core::budget::{DeadlineExceeded, Interrupted};
    use packetcraftr_core::error::BoundaryError;

    use super::*;
    use crate::StatsOverflow;

    struct Recorder;

    impl Errors for Recorder {
        type Error = (&'static str, u64, String);
        type Step = ();

        fn invalid_limit(&self, field: &'static str, value: u64, reason: String) -> Self::Error {
            (field, value, reason)
        }
        fn authorization(&self, _: BoundaryError) -> Self::Error {
            unreachable!("check_rate reports only invalid limits")
        }
        fn duration_limit(&self, (): (), _: DeadlineExceeded) -> Self::Error {
            unreachable!("check_rate reports only invalid limits")
        }
        fn interrupted(&self, (): (), _: Interrupted) -> Self::Error {
            unreachable!("check_rate reports only invalid limits")
        }
        fn clock(&self, (): (), _: Box<dyn std::error::Error + Send + Sync>) -> Self::Error {
            unreachable!("check_rate reports only invalid limits")
        }
        fn execution(&self, (): (), _: BoundaryError) -> Self::Error {
            unreachable!("check_rate reports only invalid limits")
        }
        fn invalid_evidence(&self, (): (), _: crate::evidence::Error) -> Self::Error {
            unreachable!("check_rate reports only invalid limits")
        }
        fn stats_overflow(&self, (): (), _: StatsOverflow) -> Self::Error {
            unreachable!("check_rate reports only invalid limits")
        }
    }

    #[test]
    fn check_rate_accepts_an_absent_rate_and_every_rate_up_to_the_ceiling() {
        for rate in [None, Some(1), Some(MAX_RATE)] {
            assert_eq!(check_rate(&Recorder, "rate", rate), Ok(()));
        }
    }

    #[test]
    fn check_rate_rejects_zero_and_rates_above_the_ceiling_with_the_exact_reason() {
        for rate in [0, MAX_RATE + 1, u32::MAX] {
            assert_eq!(
                check_rate(&Recorder, "probes_per_second", Some(rate)),
                Err((
                    "probes_per_second",
                    u64::from(rate),
                    "must be within 1..=1000000".to_owned()
                ))
            );
        }
    }

    #[test]
    fn duration_violation_rejects_zero_and_anything_past_the_maximum() {
        let maximum = packetcraftr_netio::deadline::MAX_WAIT;
        assert!(duration_violation(Duration::ZERO, maximum));
        assert!(duration_violation(
            maximum + Duration::from_nanos(1),
            maximum
        ));
        assert!(!duration_violation(Duration::from_nanos(1), maximum));
        assert!(!duration_violation(maximum, maximum));
    }

    fn validate_evidence(
        max_frames: usize,
        max_bytes: usize,
        max_undecoded: usize,
    ) -> Result<(), (&'static str, u64, String)> {
        EvidenceLimits {
            max_frames,
            max_bytes,
            max_undecoded,
        }
        .validate(|field, value, reason| (field, value, reason))
    }

    #[test]
    fn evidence_limits_accept_every_bound_up_to_the_capture_queue_ceilings() {
        use packetcraftr_netio::capture::{MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES};

        assert_eq!(validate_evidence(1, 1, 0), Ok(()));
        assert_eq!(validate_evidence(4, 4096, 4), Ok(()));
        assert_eq!(
            validate_evidence(
                MAX_CAPTURE_QUEUE_FRAMES,
                MAX_CAPTURE_QUEUE_BYTES,
                MAX_CAPTURE_QUEUE_FRAMES
            ),
            Ok(())
        );
    }

    #[test]
    fn evidence_limits_reject_out_of_range_queues_and_undecoded_frames_beyond_the_frame_budget() {
        use packetcraftr_netio::capture::{MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES};

        let frames = |value: usize| {
            (
                "max_evidence_frames",
                u64::try_from(value).unwrap(),
                format!("must be within 1..={MAX_CAPTURE_QUEUE_FRAMES}"),
            )
        };
        let bytes = |value: usize| {
            (
                "max_evidence_bytes",
                u64::try_from(value).unwrap(),
                format!("must be within 1..={MAX_CAPTURE_QUEUE_BYTES}"),
            )
        };
        assert_eq!(validate_evidence(0, 1, 0), Err(frames(0)));
        assert_eq!(
            validate_evidence(MAX_CAPTURE_QUEUE_FRAMES + 1, 1, 0),
            Err(frames(MAX_CAPTURE_QUEUE_FRAMES + 1))
        );
        assert_eq!(validate_evidence(1, 0, 0), Err(bytes(0)));
        assert_eq!(
            validate_evidence(1, MAX_CAPTURE_QUEUE_BYTES + 1, 0),
            Err(bytes(MAX_CAPTURE_QUEUE_BYTES + 1))
        );
        assert_eq!(
            validate_evidence(4, 1, 5),
            Err((
                "max_undecoded",
                5,
                "cannot exceed max_evidence_frames".to_owned()
            ))
        );
    }
}
