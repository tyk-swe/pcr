// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::domain::spec::TransmissionSpec;
pub type TransmissionPolicy = crate::domain::policy::TransmissionPolicy;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SendControlError {
    #[error("--flood without --count requires explicit unbounded-send opt-in")]
    FloodRequiresCount,
    #[error("--loop requires explicit unbounded-send opt-in")]
    LoopRequiresAllowUnbounded,
    #[error("--count must be greater than zero")]
    CountMustBePositive,
    #[error(
        "emitted unit count overflows u64: attempts={attempts} units_per_attempt={units_per_attempt}"
    )]
    EmittedUnitsOverflow {
        attempts: u64,
        units_per_attempt: u64,
    },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmissionAccounting {
    pub attempts: Option<u64>,
    pub units_per_attempt: u64,
    pub total_emitted_units: Option<u64>,
}

pub fn emission_accounting(
    spec: &TransmissionSpec,
    policy: TransmissionPolicy,
    units_per_attempt: u64,
) -> Result<EmissionAccounting, SendControlError> {
    let attempts = match determine_send_mode(spec, policy)? {
        SendMode::Finite(count) => Some(count),
        SendMode::Infinite => None,
    };
    let total_emitted_units = attempts
        .map(|count| {
            count
                .checked_mul(units_per_attempt)
                .ok_or(SendControlError::EmittedUnitsOverflow {
                    attempts: count,
                    units_per_attempt,
                })
        })
        .transpose()?;

    Ok(EmissionAccounting {
        attempts,
        units_per_attempt,
        total_emitted_units,
    })
}
