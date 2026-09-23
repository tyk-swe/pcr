// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::decode::Dissector;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::registry::Registry;

use crate::evidence::{Budget, DiagnosticLog};
use crate::probe::evidence::{
    format_exchange_evidence_error, validate_response_frames_and_deadlines,
};

use super::error::{Error, duration_limit};
use super::execution::Execution;
use super::{Case, CaseOutcome, LiveLimits};

/// Turns each validated live execution into its case's evidence: the decoded
/// sent packet, the exact frames retained under the campaign-wide evidence
/// budget, and the response-or-timeout outcome.
pub(super) struct Recorder {
    dissector: Dissector,
    decode_limits: packet_fuzz::Limits,
    retention: LiveLimits,
    budget: Budget,
    diagnostics: DiagnosticLog,
}

impl Recorder {
    pub(super) fn new(
        registry: Arc<Registry>,
        decode_limits: packet_fuzz::Limits,
        retention: LiveLimits,
    ) -> Self {
        Self {
            dissector: Dissector::new(registry),
            decode_limits,
            retention,
            budget: Budget::default(),
            diagnostics: DiagnosticLog::default(),
        }
    }

    pub(super) fn record(
        &mut self,
        case: &mut Case,
        execution: Execution,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        let had_response = !execution.responses.is_empty();
        case.prepared.diagnostics = execution.sent.built().diagnostics.clone();
        case.prepared.decoded = packet_fuzz::dissect_built(
            &self.dissector,
            execution.sent.built(),
            self.decode_limits,
            &mut case.prepared.diagnostics,
        );
        deadline.enforce()?;
        case.prepared.built = Some(execution.sent.built().clone());
        case.sent = Some(execution.sent.frame().clone());
        case.prepared.diagnostics.extend(execution.diagnostics);
        retain_evidence(
            case,
            ExecutionEvidence {
                responses: execution
                    .responses
                    .into_iter()
                    .map(|response| response.response.frame)
                    .collect(),
                unmatched: execution.unmatched,
                undecoded: execution.undecoded,
            },
            self.retention,
            &mut self.budget,
            &mut self.diagnostics,
            deadline,
        )?;
        case.outcome = if had_response {
            CaseOutcome::Response
        } else {
            CaseOutcome::Timeout
        };
        deadline.enforce()?;
        Ok(())
    }

    /// Campaign-level diagnostics reach the caller on the case they were
    /// raised during; the campaign never republishes them.
    pub(super) fn publish_diagnostics(&mut self, case: &mut Case) -> Result<(), Error> {
        self.diagnostics.publish_new::<Error>(|diagnostic| {
            case.prepared.diagnostics.push(diagnostic);
            Ok(())
        })
    }
}

pub(super) fn validate_execution(
    case: &Case,
    execution: &Execution,
    timeout: Duration,
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
    deadline.check().map_err(duration_limit)?;
    validate_response_frames_and_deadlines(&execution.responses, &[], timeout).map_err(
        |error| Error::InvalidEvidence {
            case_index: case.prepared.index,
            message: format_exchange_evidence_error(error, "case", "fuzz"),
        },
    )?;
    deadline.check().map_err(duration_limit)?;
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

struct ExecutionEvidence {
    responses: Vec<Frame>,
    unmatched: Vec<Frame>,
    undecoded: Vec<Frame>,
}

fn retain_evidence(
    case: &mut Case,
    evidence: ExecutionEvidence,
    limits: LiveLimits,
    budget: &mut Budget,
    diagnostics: &mut DiagnosticLog,
    deadline: &Deadline,
) -> Result<(), Error> {
    let mut omitted = false;
    let mut retain = |frames: Vec<Frame>, sink: &mut Vec<Frame>| -> Result<(), Error> {
        for frame in frames {
            deadline.check().map_err(duration_limit)?;
            if retain_fuzz_evidence(budget, &frame, limits) {
                sink.push(frame);
            } else {
                omitted = true;
            }
        }
        Ok(())
    };
    retain(evidence.responses, &mut case.responses)?;
    retain(evidence.unmatched, &mut case.unmatched)?;
    retain(evidence.undecoded, &mut case.undecoded)?;
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
