// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact live fuzz executor-evidence validation, accounting, and retention.

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::evidence::{Budget, DiagnosticLog};

use super::error::{Error, duration_limit};
use super::execution::Execution;
use super::report::{Case, Stats};
use super::request::LiveLimits;

pub(super) fn validate_execution(
    case: &Case,
    execution: &Execution,
    max_packet_bytes: usize,
    deadline: &Deadline,
) -> Result<(), Error> {
    if execution.stats.packets_attempted != 1 || execution.stats.packets_completed != 1 {
        return Err(Error::InvalidEvidence {
            case_index: case.prepared.index,
            message: "successful live execution must account for exactly one attempted and completed packet".to_owned(),
        });
    }
    if execution.stats.bytes != u64::try_from(execution.sent.bytes_sent()).unwrap_or(u64::MAX) {
        return Err(Error::InvalidEvidence {
            case_index: case.prepared.index,
            message: "sent receipt and byte statistics disagree".to_owned(),
        });
    }
    if execution.sent.built().bytes.len() > max_packet_bytes {
        return Err(Error::InvalidEvidence {
            case_index: case.prepared.index,
            message: format!(
                "executor built {} bytes, exceeding max_packet_bytes={}",
                execution.sent.built().bytes.len(),
                max_packet_bytes
            ),
        });
    }
    execution
        .stats
        .capture
        .validate()
        .map_err(|source| Error::InvalidEvidence {
            case_index: case.prepared.index,
            message: format!("invalid capture statistics: {source}"),
        })?;
    for response in &execution.responses {
        deadline.check().map_err(duration_limit)?;
        let Some(_received_at) = response.timestamp else {
            return Err(Error::InvalidEvidence {
                case_index: case.prepared.index,
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
) -> Result<(), Error> {
    let mut sum = total.clone();
    macro_rules! add {
        ($field:ident) => {
            sum.$field = sum
                .$field
                .checked_add(value.$field)
                .ok_or(Error::StatisticsOverflow { case_index })?;
        };
    }
    add!(packets_attempted);
    add!(packets_completed);
    add!(bytes);
    sum.elapsed = sum
        .elapsed
        .checked_add(value.elapsed)
        .ok_or(Error::StatisticsOverflow { case_index })?;
    sum.capture = sum
        .capture
        .checked_add(value.capture)
        .ok_or(Error::StatisticsOverflow { case_index })?;
    *total = sum;
    Ok(())
}

fn retain_fuzz_evidence(budget: &mut Budget, frame: &Frame, limits: LiveLimits) -> bool {
    budget
        .reserve(
            frame.bytes().len(),
            limits.max_evidence_frames,
            limits.max_evidence_bytes,
        )
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
    limits: LiveLimits,
    budget: &mut Budget,
    diagnostics: &mut DiagnosticLog,
    deadline: &Deadline,
) -> Result<(), Error> {
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
        diagnostics.push_once(Diagnostic::warning(
            "fuzz.evidence_limit",
            format!(
                "fuzz response evidence exceeded {} frame(s) or {} byte(s); later exact frames were omitted",
                limits.max_evidence_frames, limits.max_evidence_bytes
            ),
        ));
    }
    deadline.check().map_err(duration_limit)?;
    Ok(())
}
