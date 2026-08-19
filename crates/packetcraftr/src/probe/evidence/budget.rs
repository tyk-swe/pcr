// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Checked evidence accounting and bounded diagnostic emission.

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::evidence::{Budget, BudgetError};

#[derive(Clone, Copy)]
pub(crate) struct EvidenceDiagnosticDescriptor {
    code_namespace: &'static str,
    display_name: &'static str,
}

impl EvidenceDiagnosticDescriptor {
    pub(crate) const fn new(code_namespace: &'static str, display_name: &'static str) -> Self {
        Self {
            code_namespace,
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
    diagnostics: &mut Vec<Diagnostic>,
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
    packetcraftr_core::diagnostic::push_once(
        diagnostics,
        Diagnostic::warning(
            format!("{}.evidence_limit", descriptor.code_namespace),
            message,
        ),
    );
    false
}

pub(crate) fn push_undecoded_limit_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    descriptor: EvidenceDiagnosticDescriptor,
    limit: usize,
) {
    packetcraftr_core::diagnostic::push_once(
        diagnostics,
        Diagnostic::warning(
            format!("{}.undecoded_limit", descriptor.code_namespace),
            format!(
                "undecodable {} evidence limit {limit} reached; later frames were omitted",
                descriptor.display_name
            ),
        ),
    );
}

/// Applies the operation-wide evidence budget and undecoded retention cap in
/// one place while allowing workflows to retain their own typed wrapper.
#[expect(
    clippy::too_many_arguments,
    reason = "the retention seam threads the frame batch, its output sink, and every bound that \
              caps it; a parameter struct would only rename the same fields"
)]
pub(crate) fn retain_undecoded_frames<T, E>(
    frames: Vec<Frame>,
    retained_count: &mut usize,
    max_undecoded: usize,
    budget: &mut Budget,
    descriptor: EvidenceDiagnosticDescriptor,
    max_evidence_frames: usize,
    max_evidence_bytes: usize,
    diagnostics: &mut Vec<Diagnostic>,
    mut map: impl FnMut(Frame) -> T,
    mut emit: impl FnMut(T) -> Result<(), E>,
    mut check_deadline: impl FnMut() -> Result<(), E>,
) -> Result<(), E> {
    for frame in frames {
        check_deadline()?;
        if *retained_count >= max_undecoded {
            push_undecoded_limit_diagnostic(diagnostics, descriptor, max_undecoded);
            break;
        }
        if retain_evidence(
            budget,
            &frame,
            descriptor,
            max_evidence_frames,
            max_evidence_bytes,
            diagnostics,
        ) {
            *retained_count += 1;
            emit(map(frame))?;
        }
        check_deadline()?;
    }
    Ok(())
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
