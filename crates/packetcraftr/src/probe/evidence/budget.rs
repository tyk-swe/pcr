// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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

#[derive(Clone, Copy, Debug)]
pub(crate) struct EvidenceLimits {
    pub(crate) max_frames: usize,
    pub(crate) max_bytes: usize,
    pub(crate) max_undecoded: usize,
}

/// Where a workflow publishes what [`EvidenceState`] keeps, as the
/// workflow's own events, and how it checks its deadline between frames.
pub(crate) trait EvidenceSink {
    type Error;

    /// Publishes one retained undecodable frame.
    fn undecoded(&mut self, frame: Frame) -> Result<(), Self::Error>;
    /// Publishes one diagnostic.
    fn diagnostic(&mut self, diagnostic: Diagnostic) -> Result<(), Self::Error>;
    /// Checks the operation deadline around each undecodable frame.
    fn check(&mut self) -> Result<(), Self::Error>;
}

/// Operation-wide evidence accounting shared by live workflows: the exact
/// frame budget, how many undecodable frames were kept, and the diagnostics
/// raised while keeping them, each published once.
pub(crate) struct EvidenceState {
    limits: EvidenceLimits,
    descriptor: EvidenceDiagnosticDescriptor,
    budget: Budget,
    retained_undecoded: usize,
    diagnostics: DiagnosticLog,
}

impl EvidenceState {
    pub(crate) fn new(limits: EvidenceLimits, descriptor: EvidenceDiagnosticDescriptor) -> Self {
        Self {
            limits,
            descriptor,
            budget: Budget::default(),
            retained_undecoded: 0,
            diagnostics: DiagnosticLog::default(),
        }
    }

    /// Keeps a copy of `frame` when the budget allows it, otherwise records a
    /// truncation diagnostic once.
    pub(crate) fn retain_response(&mut self, frame: &Frame) -> Option<Frame> {
        self.reserve(frame).then(|| frame.clone())
    }

    /// Publishes every retained undecodable frame and every new diagnostic in
    /// arrival order, stopping at the undecoded limit with its diagnostic.
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
            if self.reserve(&frame) {
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

    /// Records each diagnostic once and publishes the ones not yet published.
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

    /// Publishes every diagnostic recorded since the last publication.
    pub(crate) fn publish_diagnostics<E>(
        &mut self,
        publish: impl FnMut(Diagnostic) -> Result<(), E>,
    ) -> Result<(), E> {
        self.diagnostics.publish_new(publish)
    }

    /// Charges `frame` to the budget, or records why it was omitted.
    fn reserve(&mut self, frame: &Frame) -> bool {
        let EvidenceLimits {
            max_frames,
            max_bytes,
            ..
        } = self.limits;
        let error = match self
            .budget
            .reserve(frame.bytes().len(), max_frames, max_bytes)
        {
            Ok(()) => return true,
            Err(error) => error,
        };
        let name = self.descriptor.display_name;
        let message = match error {
            BudgetError::FrameCountOverflow => {
                format!("{name} evidence frame accounting overflowed; later frames were omitted")
            }
            BudgetError::ByteCountOverflow => {
                format!("{name} evidence byte accounting overflowed; later frames were omitted")
            }
            BudgetError::FrameLimit | BudgetError::ByteLimit => format!(
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
