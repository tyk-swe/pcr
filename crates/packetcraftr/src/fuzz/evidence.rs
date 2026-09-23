// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::decode::Dissector;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::registry::Registry;

use crate::probe::evidence::{
    EvidenceDiagnosticDescriptor, EvidenceState, format_exchange_evidence_error,
    validate_response_frames_and_deadlines,
};

use super::error::{Error, duration_limit};
use super::execution::Execution;
use super::{Case, CaseOutcome, LiveLimits};

/// Fuzz keeps undecodable frames as case evidence under the frame budget
/// alone, so its undecoded-limit code is never raised.
const EVIDENCE_DIAGNOSTICS: EvidenceDiagnosticDescriptor = EvidenceDiagnosticDescriptor::new(
    "fuzz.evidence_limit",
    "fuzz.undecoded_limit",
    "fuzz response",
);

/// Turns each validated live execution into its case's evidence: the decoded
/// sent packet, the exact frames retained under the campaign-wide evidence
/// budget, and the response-or-timeout outcome.
pub(super) struct Recorder {
    dissector: Dissector,
    decode_limits: packet_fuzz::Limits,
    evidence: EvidenceState,
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
            evidence: EvidenceState::new(retention.evidence(), EVIDENCE_DIAGNOSTICS),
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
        let responses = execution
            .responses
            .into_iter()
            .map(|response| response.response.frame);
        self.retain(responses, &mut case.responses, deadline)?;
        self.retain(execution.unmatched, &mut case.unmatched, deadline)?;
        self.retain(execution.undecoded, &mut case.undecoded, deadline)?;
        deadline.check().map_err(duration_limit)?;
        case.outcome = if had_response {
            CaseOutcome::Response
        } else {
            CaseOutcome::Timeout
        };
        deadline.enforce()?;
        Ok(())
    }

    /// Retains exact frames while the campaign-wide evidence budget allows,
    /// noting once that later frames were omitted.
    fn retain(
        &mut self,
        frames: impl IntoIterator<Item = Frame>,
        sink: &mut Vec<Frame>,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        for frame in frames {
            deadline.check().map_err(duration_limit)?;
            sink.extend(self.evidence.retain_response(&frame));
        }
        Ok(())
    }

    /// Campaign-level diagnostics reach the caller on the case they were
    /// raised during; the campaign never republishes them.
    pub(super) fn publish_diagnostics(&mut self, case: &mut Case) -> Result<(), Error> {
        self.evidence.publish_diagnostics::<Error>(|diagnostic| {
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
