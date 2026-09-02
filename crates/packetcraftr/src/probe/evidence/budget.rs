// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Checked evidence accounting and bounded diagnostic emission.

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::evidence::{Budget, BudgetError, DiagnosticLog};

#[derive(Clone, Copy)]
pub(crate) struct EvidenceDiagnosticDescriptor {
    evidence_limit_code: &'static str,
    undecoded_limit_code: &'static str,
    display_name: &'static str,
}

impl EvidenceDiagnosticDescriptor {
    pub(crate) const fn new(
        evidence_limit_code: &'static str,
        undecoded_limit_code: &'static str,
        display_name: &'static str,
    ) -> Self {
        Self {
            evidence_limit_code,
            undecoded_limit_code,
            display_name,
        }
    }
}

pub(crate) fn retain_evidence(
    budget: &mut Budget,
    frame: &Frame,
    descriptor: EvidenceDiagnosticDescriptor,
    max_frames: usize,
    max_bytes: usize,
    diagnostics: &mut DiagnosticLog,
) -> bool {
    let error = match budget.reserve(frame.bytes().len(), max_frames, max_bytes) {
        Ok(()) => return true,
        Err(error) => error,
    };
    let message = match error {
        BudgetError::FrameCountOverflow => format!(
            "{} evidence frame accounting overflowed; later frames were omitted",
            descriptor.display_name
        ),
        BudgetError::ByteCountOverflow => format!(
            "{} evidence byte accounting overflowed; later frames were omitted",
            descriptor.display_name
        ),
        BudgetError::FrameLimit | BudgetError::ByteLimit => format!(
            "{} evidence exceeded {max_frames} frame(s) or {max_bytes} byte(s); later exact frames were omitted",
            descriptor.display_name
        ),
    };
    diagnostics.push_once(Diagnostic::warning(descriptor.evidence_limit_code, message));
    false
}

pub(crate) fn push_undecoded_limit_diagnostic(
    diagnostics: &mut DiagnosticLog,
    descriptor: EvidenceDiagnosticDescriptor,
    limit: usize,
) {
    diagnostics.push_once(Diagnostic::warning(
        descriptor.undecoded_limit_code,
        format!(
            "undecodable {} evidence limit {limit} reached; later frames were omitted",
            descriptor.display_name
        ),
    ));
}

/// Operation-wide evidence state for retaining undecodable frames.
pub(crate) struct UndecodedRetention<'a> {
    retained_count: &'a mut usize,
    max_undecoded: usize,
    budget: &'a mut Budget,
    descriptor: EvidenceDiagnosticDescriptor,
    max_evidence_frames: usize,
    max_evidence_bytes: usize,
    diagnostics: &'a mut DiagnosticLog,
}

impl<'a> UndecodedRetention<'a> {
    pub(crate) fn new(
        retained_count: &'a mut usize,
        max_undecoded: usize,
        budget: &'a mut Budget,
        descriptor: EvidenceDiagnosticDescriptor,
        max_evidence_frames: usize,
        max_evidence_bytes: usize,
        diagnostics: &'a mut DiagnosticLog,
    ) -> Self {
        Self {
            retained_count,
            max_undecoded,
            budget,
            descriptor,
            max_evidence_frames,
            max_evidence_bytes,
            diagnostics,
        }
    }

    pub(crate) fn retain<T, E>(
        &mut self,
        frames: Vec<Frame>,
        mut map: impl FnMut(Frame) -> T,
        mut map_diagnostic: impl FnMut(Diagnostic) -> T,
        mut emit: impl FnMut(T) -> Result<(), E>,
        mut check_deadline: impl FnMut() -> Result<(), E>,
    ) -> Result<(), E> {
        for frame in frames {
            check_deadline()?;
            if *self.retained_count >= self.max_undecoded {
                push_undecoded_limit_diagnostic(
                    self.diagnostics,
                    self.descriptor,
                    self.max_undecoded,
                );
                self.diagnostics
                    .publish_new(|diagnostic| emit(map_diagnostic(diagnostic)))?;
                break;
            }
            if retain_evidence(
                self.budget,
                &frame,
                self.descriptor,
                self.max_evidence_frames,
                self.max_evidence_bytes,
                self.diagnostics,
            ) {
                #[expect(
                    clippy::arithmetic_side_effects,
                    reason = "`retain_evidence` returns false once the count reaches \
                              `max_evidence_frames`, so the increment cannot overflow"
                )]
                {
                    *self.retained_count += 1;
                }
                emit(map(frame))?;
            }
            self.diagnostics
                .publish_new(|diagnostic| emit(map_diagnostic(diagnostic)))?;
            check_deadline()?;
        }
        Ok(())
    }
}

pub(crate) fn checked_frame_count(counts: &[usize]) -> Option<usize> {
    counts
        .iter()
        .try_fold(0_usize, |total, count| total.checked_add(*count))
}

pub(crate) fn checked_frame_bytes<'a>(
    frames: impl IntoIterator<Item = &'a Frame>,
) -> Option<usize> {
    frames.into_iter().try_fold(0_usize, |total, frame| {
        total.checked_add(frame.bytes().len())
    })
}
