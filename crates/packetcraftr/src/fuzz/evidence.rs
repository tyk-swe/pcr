// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::decode::Dissector;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::registry::Registry;

use crate::execution::evidence::{EvidenceDiagnosticDescriptor, EvidenceState};
use crate::execution::validation::{
    validate_capture_statistics_evidence, validate_response_frames_and_deadlines,
    validate_sent_byte_accounting,
};

use super::error::{CaseErrors, Error, duration_limit};
use super::executor::CaseEvidence;
use super::{Evidence, Outcome};
use crate::execution::Errors as _;
use crate::execution::limits::EvidenceLimits;

/// Fuzz keeps undecodable frames as case evidence under the frame budget
/// alone, so its undecoded-limit code is never raised.
const EVIDENCE_DIAGNOSTICS: EvidenceDiagnosticDescriptor = EvidenceDiagnosticDescriptor::new(
    "fuzz.evidence_limit",
    "fuzz.undecoded_limit",
    "fuzz response",
);

pub(super) struct Recorder {
    dissector: Dissector,
    decode_limits: packet_fuzz::Limits,
    evidence: EvidenceState,
}

impl Recorder {
    pub(super) fn new(
        registry: Arc<Registry>,
        decode_limits: packet_fuzz::Limits,
        retention: EvidenceLimits,
    ) -> Self {
        Self {
            dissector: Dissector::new(registry),
            decode_limits,
            evidence: EvidenceState::new(retention, EVIDENCE_DIAGNOSTICS),
        }
    }

    pub(super) fn record(
        &mut self,
        case: &mut packet_fuzz::Case,
        execution: CaseEvidence,
        deadline: &Deadline,
    ) -> Result<Evidence, Error> {
        let had_response = !execution.responses.is_empty();
        // The oracle's verdicts were reached when the case was prepared; the
        // executed bytes are the same case, so they are kept, not recomputed.
        let roundtrip = case
            .diagnostics
            .iter()
            .filter(|diagnostic| packet_fuzz::is_roundtrip_diagnostic(diagnostic))
            .cloned()
            .collect::<Vec<_>>();
        case.diagnostics = execution.sent.built().diagnostics.clone();
        case.decoded = packet_fuzz::dissect_built(
            &self.dissector,
            execution.sent.built(),
            self.decode_limits,
            &mut case.diagnostics,
        );
        case.diagnostics.extend(roundtrip);
        deadline.enforce()?;
        case.built = Some(execution.sent.built().clone());
        case.diagnostics.extend(execution.diagnostics);
        let mut evidence = Evidence {
            sent: execution.sent.frame().clone(),
            outcome: if had_response {
                Outcome::Response
            } else {
                Outcome::Timeout
            },
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
        };
        let responses = execution
            .responses
            .into_iter()
            .map(|response| response.response.frame);
        self.retain(responses, &mut evidence.responses, deadline)?;
        self.retain(execution.unmatched, &mut evidence.unmatched, deadline)?;
        self.retain(execution.undecoded, &mut evidence.undecoded, deadline)?;
        deadline.enforce()?;
        Ok(evidence)
    }

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

    pub(super) fn publish_diagnostics(
        &mut self,
        case: &mut packet_fuzz::Case,
    ) -> Result<(), Error> {
        self.evidence.publish_diagnostics::<Error>(|diagnostic| {
            case.diagnostics.push(diagnostic);
            Ok(())
        })
    }
}

pub(super) fn validate_execution(
    case: &packet_fuzz::Case,
    execution: &CaseEvidence,
    timeout: Duration,
    max_packet_bytes: usize,
) -> Result<(), Error> {
    let invalid = |source| CaseErrors.invalid_evidence(case.index, source);
    if execution.stats.packets_attempted != 1 || execution.stats.packets_completed != 1 {
        return Err(invalid(crate::evidence::Error::IncompleteStatistics));
    }
    validate_sent_byte_accounting(std::slice::from_ref(&execution.sent), execution.stats.bytes)
        .map_err(invalid)?;
    if execution.sent.built().bytes.len() > max_packet_bytes {
        return Err(Error::InvalidEvidence {
            case_index: case.index,
            message: format!(
                "executor built {} bytes, exceeding max_packet_bytes={}",
                execution.sent.built().bytes.len(),
                max_packet_bytes
            ),
        });
    }
    validate_capture_statistics_evidence(execution.stats.capture).map_err(invalid)?;
    validate_response_frames_and_deadlines(&execution.responses, &[], timeout).map_err(invalid)
}
