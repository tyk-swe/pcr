// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::diagnostic::{Diagnostic, push_diagnostic_once};
use packetcraftr_core::frame::Frame;
use packetcraftr_core::fuzz::Limits;

use crate::probe::evidence::EvidenceBudget;

use super::MAX_DURATION;
use super::boundary::FuzzCaseExecution;
use super::error::{FuzzError, duration_limit};
use super::request::LiveOptions;
use super::result::{Case, Stats};

pub(super) fn worst_case_duration(live: LiveOptions, cases: usize) -> Result<Duration, FuzzError> {
    let exchange = live
        .timeout
        .checked_mul(u32::try_from(cases).unwrap_or(u32::MAX))
        .ok_or(FuzzError::DurationLimit {
            actual: Duration::MAX,
            limit: MAX_DURATION,
        })?;
    let delay = rate_delay(live.cases_per_second)?
        .checked_mul(u32::try_from(cases.saturating_sub(1)).unwrap_or(u32::MAX))
        .ok_or(FuzzError::DurationLimit {
            actual: Duration::MAX,
            limit: MAX_DURATION,
        })?;
    exchange.checked_add(delay).ok_or(FuzzError::DurationLimit {
        actual: Duration::MAX,
        limit: MAX_DURATION,
    })
}

pub(super) fn rate_delay(rate: Option<u32>) -> Result<Duration, FuzzError> {
    crate::clock::rate_delay(1, rate).ok_or(FuzzError::InvalidLimit {
        field: "cases_per_second",
        value: u64::from(rate.unwrap_or_default()),
        reason: "rate-delay arithmetic overflowed".to_owned(),
    })
}

pub(super) fn validate_execution(
    case: &Case,
    execution: &FuzzCaseExecution,
    limits: Limits,
    _timeout: Duration,
    deadline: &Deadline,
) -> Result<(), FuzzError> {
    if execution.stats.packets_attempted != 1 || execution.stats.packets_completed != 1 {
        return Err(FuzzError::InvalidEvidence {
            case_index: case.index,
            message: "successful live execution must account for exactly one attempted and completed packet".to_owned(),
        });
    }
    if execution.stats.bytes != u64::try_from(execution.sent.bytes_sent()).unwrap_or(u64::MAX) {
        return Err(FuzzError::InvalidEvidence {
            case_index: case.index,
            message: "sent receipt and byte statistics disagree".to_owned(),
        });
    }
    if execution.sent.built().bytes.len() > limits.max_packet_bytes {
        return Err(FuzzError::InvalidEvidence {
            case_index: case.index,
            message: format!(
                "executor built {} bytes, exceeding max_packet_bytes={}",
                execution.sent.built().bytes.len(),
                limits.max_packet_bytes
            ),
        });
    }
    execution
        .stats
        .capture
        .validate()
        .map_err(|source| FuzzError::InvalidEvidence {
            case_index: case.index,
            message: format!("invalid capture statistics: {source}"),
        })?;
    for response in &execution.responses {
        deadline.check().map_err(duration_limit)?;
        let Some(_received_at) = response.timestamp else {
            return Err(FuzzError::InvalidEvidence {
                case_index: case.index,
                message: "executor returned response frame without a timestamp".to_owned(),
            });
        };
    }
    deadline.check().map_err(duration_limit)?;
    Ok(())
}

pub(super) fn add_execution_stats(
    total: &mut Stats,
    value: &crate::Stats,
    case_index: u64,
) -> Result<(), FuzzError> {
    let mut sum = total.clone();
    macro_rules! add {
        ($field:ident) => {
            sum.$field = sum
                .$field
                .checked_add(value.$field)
                .ok_or(FuzzError::StatisticsOverflow { case_index })?;
        };
    }
    add!(packets_attempted);
    add!(packets_completed);
    add!(bytes);
    sum.elapsed = sum
        .elapsed
        .checked_add(value.elapsed)
        .ok_or(FuzzError::StatisticsOverflow { case_index })?;
    sum.capture = sum
        .capture
        .checked_add(value.capture)
        .ok_or(FuzzError::StatisticsOverflow { case_index })?;
    *total = sum;
    Ok(())
}

fn retain_fuzz_evidence(budget: &mut EvidenceBudget, frame: &Frame, limits: Limits) -> bool {
    budget
        .retain(frame, limits.max_evidence_frames, limits.max_evidence_bytes)
        .is_ok()
}

pub(super) struct ExecutionEvidence {
    pub(super) responses: Vec<Frame>,
    pub(super) unmatched: Vec<Frame>,
    pub(super) undecoded: Vec<Frame>,
}

pub(super) fn retain_evidence(
    case: &mut Case,
    evidence: ExecutionEvidence,
    limits: Limits,
    budget: &mut EvidenceBudget,
    diagnostics: &mut Vec<Diagnostic>,
    deadline: &Deadline,
) -> Result<(), FuzzError> {
    let mut omitted = false;
    for frame in evidence.responses {
        deadline.check().map_err(duration_limit)?;
        if retain_fuzz_evidence(budget, &frame, limits) {
            case.responses.push(frame);
        } else {
            omitted = true;
        }
    }
    for frame in evidence.unmatched {
        deadline.check().map_err(duration_limit)?;
        if retain_fuzz_evidence(budget, &frame, limits) {
            case.unmatched.push(frame);
        } else {
            omitted = true;
        }
    }
    for frame in evidence.undecoded {
        deadline.check().map_err(duration_limit)?;
        if retain_fuzz_evidence(budget, &frame, limits) {
            case.undecoded.push(frame);
        } else {
            omitted = true;
        }
    }
    if omitted {
        push_diagnostic_once(
            diagnostics,
            Diagnostic::warning(
                "fuzz.evidence_limit",
                format!(
                    "fuzz response evidence exceeded {} frame(s) or {} byte(s); later exact frames were omitted",
                    limits.max_evidence_frames, limits.max_evidence_bytes
                ),
            ),
        );
    }
    deadline.check().map_err(duration_limit)?;
    Ok(())
}
