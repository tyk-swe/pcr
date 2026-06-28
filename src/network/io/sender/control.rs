// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::engine::spec::TransmissionSpec;
pub type TransmissionPolicy = crate::engine::policy::TransmissionPolicy;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SendControlError {
    #[error("--flood without --count requires explicit unbounded-send opt-in")]
    FloodRequiresCount,
    #[error("--loop requires explicit unbounded-send opt-in")]
    LoopRequiresAllowUnbounded,
    #[error("--count must be greater than zero")]
    CountMustBePositive,
}

pub fn validate_transmission_policy(
    spec: &TransmissionSpec,
    policy: TransmissionPolicy,
) -> Result<(), SendControlError> {
    if matches!(spec.count, Some(0)) {
        return Err(SendControlError::CountMustBePositive);
    }

    if spec.loop_send && !policy.allow_unbounded_sends {
        return Err(SendControlError::LoopRequiresAllowUnbounded);
    }

    if spec.flood && spec.count.is_none() && !policy.allow_unbounded_sends {
        return Err(SendControlError::FloodRequiresCount);
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SendMode {
    Finite(u64),
    Infinite,
}

pub(crate) fn determine_send_mode(
    spec: &TransmissionSpec,
    policy: TransmissionPolicy,
) -> Result<SendMode, SendControlError> {
    validate_transmission_policy(spec, policy)?;

    if spec.loop_send {
        Ok(SendMode::Infinite)
    } else if let Some(count) = spec.count {
        Ok(SendMode::Finite(count))
    } else if spec.flood {
        Ok(SendMode::Infinite)
    } else {
        Ok(SendMode::Finite(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_policy() -> TransmissionPolicy {
        TransmissionPolicy::default()
    }

    fn allow_unbounded_policy() -> TransmissionPolicy {
        TransmissionPolicy::new(true, false)
    }

    fn dry_run_policy() -> TransmissionPolicy {
        TransmissionPolicy::new(false, true)
    }

    #[test]
    fn determine_send_mode_rejects_loop_without_unbounded_opt_in() {
        let spec = TransmissionSpec {
            loop_send: true,
            count: None,
            flood: false,
            ..Default::default()
        };
        assert!(matches!(
            determine_send_mode(&spec, strict_policy()),
            Err(SendControlError::LoopRequiresAllowUnbounded)
        ));
    }

    #[test]
    fn determine_send_mode_allows_loop_with_unbounded_opt_in() {
        let spec = TransmissionSpec {
            loop_send: true,
            count: None,
            flood: false,
            ..Default::default()
        };
        assert!(matches!(
            determine_send_mode(&spec, allow_unbounded_policy()),
            Ok(SendMode::Infinite)
        ));
    }

    #[test]
    fn determine_send_mode_returns_finite_with_count() {
        let spec = TransmissionSpec {
            loop_send: false,
            count: Some(42),
            flood: false,
            ..Default::default()
        };
        match determine_send_mode(&spec, strict_policy()).expect("send mode") {
            SendMode::Finite(count) => assert_eq!(count, 42),
            _ => panic!("expected Finite mode"),
        }
    }

    #[test]
    fn determine_send_mode_rejects_flood_without_count() {
        let spec = TransmissionSpec {
            loop_send: false,
            count: None,
            flood: true,
            ..Default::default()
        };
        assert!(matches!(
            determine_send_mode(&spec, strict_policy()),
            Err(SendControlError::FloodRequiresCount)
        ));
    }

    #[test]
    fn determine_send_mode_allows_flood_without_count_with_unbounded_opt_in() {
        let spec = TransmissionSpec {
            loop_send: false,
            count: None,
            flood: true,
            ..Default::default()
        };
        assert!(matches!(
            determine_send_mode(&spec, allow_unbounded_policy()),
            Ok(SendMode::Infinite)
        ));
    }

    #[test]
    fn determine_send_mode_rejects_unbounded_flood_in_dry_run() {
        let spec = TransmissionSpec {
            loop_send: false,
            count: None,
            flood: true,
            ..Default::default()
        };
        assert!(matches!(
            determine_send_mode(&spec, dry_run_policy()),
            Err(SendControlError::FloodRequiresCount)
        ));
    }

    #[test]
    fn determine_send_mode_returns_finite_one_by_default() {
        let spec = TransmissionSpec {
            loop_send: false,
            count: None,
            flood: false,
            ..Default::default()
        };
        match determine_send_mode(&spec, strict_policy()).expect("send mode") {
            SendMode::Finite(count) => assert_eq!(count, 1),
            _ => panic!("expected Finite mode with count 1"),
        }
    }

    #[test]
    fn determine_send_mode_rejects_loop_with_count_without_unbounded_opt_in() {
        let spec = TransmissionSpec {
            loop_send: true,
            count: Some(10),
            flood: false,
            ..Default::default()
        };
        assert!(matches!(
            determine_send_mode(&spec, strict_policy()),
            Err(SendControlError::LoopRequiresAllowUnbounded)
        ));
    }

    #[test]
    fn determine_send_mode_loop_takes_precedence_over_flood_when_allowed() {
        let spec = TransmissionSpec {
            loop_send: true,
            count: None,
            flood: true,
            ..Default::default()
        };
        assert!(matches!(
            determine_send_mode(&spec, allow_unbounded_policy()),
            Ok(SendMode::Infinite)
        ));
    }

    #[test]
    fn determine_send_mode_count_takes_precedence_over_flood() {
        let spec = TransmissionSpec {
            loop_send: false,
            count: Some(5),
            flood: true,
            ..Default::default()
        };
        match determine_send_mode(&spec, strict_policy()).expect("send mode") {
            SendMode::Finite(count) => assert_eq!(count, 5),
            _ => panic!("expected Finite mode with count 5"),
        }
    }

    #[test]
    fn determine_send_mode_rejects_zero_count() {
        let spec = TransmissionSpec {
            loop_send: false,
            count: Some(0),
            flood: false,
            ..Default::default()
        };
        assert!(matches!(
            determine_send_mode(&spec, strict_policy()),
            Err(SendControlError::CountMustBePositive)
        ));
    }

    #[test]
    fn determine_send_mode_with_large_count() {
        let spec = TransmissionSpec {
            loop_send: false,
            count: Some(u64::MAX),
            flood: false,
            ..Default::default()
        };
        match determine_send_mode(&spec, strict_policy()).expect("send mode") {
            SendMode::Finite(count) => assert_eq!(count, u64::MAX),
            _ => panic!("expected Finite mode with large count"),
        }
    }
}
