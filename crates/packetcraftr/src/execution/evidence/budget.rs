// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::evidence::{DiagnosticLog, RetentionBudget, RetentionError};
use crate::execution::limits::EvidenceLimits;

#[derive(Clone, Copy)]
pub(crate) struct EvidenceDiagnosticDescriptor {
    evidence_limit_code: &'static str,
    undecoded_limit_code: &'static str,
    unattributed_limit_code: &'static str,
    display_name: &'static str,
}

impl EvidenceDiagnosticDescriptor {
    pub(crate) const fn new(
        evidence_limit_code: &'static str,
        undecoded_limit_code: &'static str,
        unattributed_limit_code: &'static str,
        display_name: &'static str,
    ) -> Self {
        Self {
            evidence_limit_code,
            undecoded_limit_code,
            unattributed_limit_code,
            display_name,
        }
    }
}

pub(crate) trait EvidenceSink {
    type Error;

    fn undecoded(&mut self, frame: Frame) -> Result<(), Self::Error>;
    fn diagnostic(&mut self, diagnostic: Diagnostic) -> Result<(), Self::Error>;
    fn check(&mut self) -> Result<(), Self::Error>;
}

pub(crate) struct EvidenceState {
    limits: EvidenceLimits,
    descriptor: EvidenceDiagnosticDescriptor,
    budget: RetentionBudget,
    retained_undecoded: usize,
    retained_unattributed: usize,
    outstanding_responses: usize,
    max_response_bytes: usize,
    diagnostics: DiagnosticLog,
}

impl EvidenceState {
    pub(crate) fn new(limits: EvidenceLimits, descriptor: EvidenceDiagnosticDescriptor) -> Self {
        Self {
            limits,
            descriptor,
            budget: RetentionBudget::default(),
            retained_undecoded: 0,
            retained_unattributed: 0,
            outstanding_responses: 0,
            max_response_bytes: 0,
            diagnostics: DiagnosticLog::default(),
        }
    }

    pub(crate) fn retain_response(&mut self, frame: &Frame) -> Option<Frame> {
        self.reserve(frame, false).then(|| frame.clone())
    }

    /// Extra replies can use only capacity beyond one maximum-size response
    /// per outstanding probe. This protects future winners across batches.
    pub(crate) fn reserve_responses(&mut self, count: usize, max_response_bytes: usize) {
        self.outstanding_responses = count;
        self.max_response_bytes = max_response_bytes;
    }

    pub(crate) fn settle_response(&mut self) {
        self.outstanding_responses = self.outstanding_responses.saturating_sub(1);
    }

    pub(crate) fn release_responses(&mut self, count: usize) {
        self.outstanding_responses = self.outstanding_responses.saturating_sub(count);
    }

    /// Retains a correlated frame no outcome carries. The undecoded count
    /// bounds these separately, so neither kind can starve the other, and
    /// both share the frame and byte budget with responses.
    pub(crate) fn retain_unattributed(&mut self, frame: &Frame) -> Option<Frame> {
        if self.retained_unattributed >= self.limits.max_undecoded {
            self.diagnostics.push_once(Diagnostic::warning(
                self.descriptor.unattributed_limit_code,
                format!(
                    "unattributed {} evidence limit {} reached; later frames were omitted",
                    self.descriptor.display_name, self.limits.max_undecoded
                ),
            ));
            return None;
        }
        if !self.reserve(frame, true) {
            return None;
        }
        self.retained_unattributed += 1;
        Some(frame.clone())
    }

    pub(crate) fn retain_undecoded<S: EvidenceSink>(
        &mut self,
        frames: Vec<Frame>,
        sink: &mut S,
    ) -> Result<(), S::Error> {
        for frame in frames {
            sink.check()?;
            if self.retained_undecoded >= self.limits.max_undecoded {
                self.diagnostics.push_once(Diagnostic::warning(
                    self.descriptor.undecoded_limit_code,
                    format!(
                        "undecodable {} evidence limit {} reached; later frames were omitted",
                        self.descriptor.display_name, self.limits.max_undecoded
                    ),
                ));
                self.publish_diagnostics(|diagnostic| sink.diagnostic(diagnostic))?;
                break;
            }
            if self.reserve(&frame, false) {
                // `reserve` fails once the count reaches `max_frames`, so the
                // increment cannot overflow.
                self.retained_undecoded += 1;
                sink.undecoded(frame)?;
            }
            self.publish_diagnostics(|diagnostic| sink.diagnostic(diagnostic))?;
            sink.check()?;
        }
        Ok(())
    }

    pub(crate) fn record_diagnostics<S: EvidenceSink>(
        &mut self,
        diagnostics: impl IntoIterator<Item = Diagnostic>,
        sink: &mut S,
    ) -> Result<(), S::Error> {
        for diagnostic in diagnostics {
            self.diagnostics.push_once(diagnostic);
        }
        self.publish_diagnostics(|diagnostic| sink.diagnostic(diagnostic))
    }

    pub(crate) fn publish_diagnostics<E>(
        &mut self,
        publish: impl FnMut(Diagnostic) -> Result<(), E>,
    ) -> Result<(), E> {
        self.diagnostics.publish_new(publish)
    }

    pub(crate) fn retained_evidence_bytes(&self) -> usize {
        self.budget.bytes()
    }

    fn reserve(&mut self, frame: &Frame, extra: bool) -> bool {
        let EvidenceLimits {
            max_frames,
            max_bytes,
            ..
        } = self.limits;
        let reserved_frames = if extra { self.outstanding_responses } else { 0 };
        let reserved_bytes = reserved_frames.saturating_mul(self.max_response_bytes);
        let error = match self.budget.reserve(
            frame.bytes().len(),
            max_frames.saturating_sub(reserved_frames),
            max_bytes.saturating_sub(reserved_bytes),
        ) {
            Ok(()) => return true,
            Err(error) => error,
        };
        let name = self.descriptor.display_name;
        let message = match error {
            RetentionError::FrameCountOverflow => {
                format!("{name} evidence frame accounting overflowed; later frames were omitted")
            }
            RetentionError::ByteCountOverflow => {
                format!("{name} evidence byte accounting overflowed; later frames were omitted")
            }
            RetentionError::FrameLimit | RetentionError::ByteLimit if reserved_frames > 0 => {
                format!(
                    "{name} evidence limit reached ({max_frames} frame(s) or {max_bytes} byte(s)); capacity for outstanding replies was reserved and extra frames were omitted"
                )
            }
            RetentionError::FrameLimit | RetentionError::ByteLimit => format!(
                "{name} evidence exceeded {max_frames} frame(s) or {max_bytes} byte(s); later exact frames were omitted"
            ),
        };
        self.diagnostics.push_once(Diagnostic::warning(
            self.descriptor.evidence_limit_code,
            message,
        ));
        false
    }
}
