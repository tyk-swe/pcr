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
    diagnostics: DiagnosticLog,
}

impl EvidenceState {
    pub(crate) fn new(limits: EvidenceLimits, descriptor: EvidenceDiagnosticDescriptor) -> Self {
        Self {
            limits,
            descriptor,
            budget: RetentionBudget::default(),
            retained_undecoded: 0,
            diagnostics: DiagnosticLog::default(),
        }
    }

    pub(crate) fn retain_response(&mut self, frame: &Frame) -> Option<Frame> {
        self.reserve(frame).then(|| frame.clone())
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
            RetentionError::FrameCountOverflow => {
                format!("{name} evidence frame accounting overflowed; later frames were omitted")
            }
            RetentionError::ByteCountOverflow => {
                format!("{name} evidence byte accounting overflowed; later frames were omitted")
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
