// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Checked evidence accounting and bounded diagnostic emission.

use packetcraftr_capture::Frame;
use packetcraftr_packet::diagnostic::{Diagnostic, push_diagnostic_once};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvidenceBudgetError {
    FrameCountOverflow,
    ByteCountOverflow,
    LimitExceeded,
}

#[derive(Default)]
pub(crate) struct EvidenceBudget {
    pub(super) retained_frame_count: usize,
    pub(super) retained_byte_count: usize,
}

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

impl EvidenceBudget {
    pub(crate) fn retain(
        &mut self,
        frame: &Frame,
        max_frames: usize,
        max_bytes: usize,
    ) -> Result<(), EvidenceBudgetError> {
        let next_frame_count = self
            .retained_frame_count
            .checked_add(1)
            .ok_or(EvidenceBudgetError::FrameCountOverflow)?;
        let next_byte_count = self
            .retained_byte_count
            .checked_add(frame.bytes().len())
            .ok_or(EvidenceBudgetError::ByteCountOverflow)?;
        if next_frame_count > max_frames || next_byte_count > max_bytes {
            return Err(EvidenceBudgetError::LimitExceeded);
        }
        self.retained_frame_count = next_frame_count;
        self.retained_byte_count = next_byte_count;
        Ok(())
    }
}

pub(crate) fn retain_evidence(
    budget: &mut EvidenceBudget,
    frame: &Frame,
    descriptor: EvidenceDiagnosticDescriptor,
    max_frames: usize,
    max_bytes: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    let error = match budget.retain(frame, max_frames, max_bytes) {
        Ok(()) => return true,
        Err(error) => error,
    };
    let message = match error {
        EvidenceBudgetError::FrameCountOverflow => format!(
            "{} evidence frame accounting overflowed; later frames were omitted",
            descriptor.display_name
        ),
        EvidenceBudgetError::ByteCountOverflow => format!(
            "{} evidence byte accounting overflowed; later frames were omitted",
            descriptor.display_name
        ),
        EvidenceBudgetError::LimitExceeded => format!(
            "{} evidence exceeded {max_frames} frame(s) or {max_bytes} byte(s); later exact frames were omitted",
            descriptor.display_name
        ),
    };
    push_diagnostic_once(
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
    push_diagnostic_once(
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

pub(crate) fn checked_sent_frame_bytes(frames: &[Frame]) -> Option<u64> {
    frames.iter().try_fold(0_u64, |total, frame| {
        total.checked_add(frame.bytes().len() as u64)
    })
}
