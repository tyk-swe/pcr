// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One permit-bound live request under a shared operation deadline. Batch
//! selection and retention happen after this boundary, in the workflow.

use std::error::Error as StdError;
use std::time::Duration;

use packetcraftr_core::budget::{Deadline, DeadlineExceeded, Interrupted};
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;

use super::evidence::{ExchangeEvidenceError, validate_captured_evidence_limits};
use super::{Executor, Request};
use crate::clock::Clock;
use crate::evidence::ExecutionPermit;
use crate::{Stats, StatsOverflow};

/// The mutable timeout and immutable permit of a request. This is deliberately
/// separate from the public executor-facing `Request` contract.
pub(crate) trait LiveRequest: Request {
    fn timeout_mut(&mut self) -> &mut Duration;
    fn permit(&self) -> ExecutionPermit;
}

/// Only the fields needed at the live boundary; workflow-specific evidence is
/// inspected by the caller's validation hook, after these common checks.
pub(crate) trait Receipt {
    fn permit(&self) -> ExecutionPermit;
    fn stats(&self) -> &Stats;
    // Batch evidence consumes these after the step; ticket 02 will use this
    // accessor when it moves that processing behind the probe interface.
    #[allow(dead_code)]
    fn diagnostics(&self) -> &[Diagnostic];
    fn matched(&self) -> &[crate::exchange::Response];
    fn unsolicited(&self) -> &[DecodedPacket] {
        &[]
    }
    fn unmatched(&self) -> &[Frame] {
        &[]
    }
    fn undecoded(&self) -> &[Frame];
}

#[derive(Clone, Copy)]
pub(crate) struct EvidenceBounds {
    pub frames: usize,
    pub bytes: usize,
}

/// Summary counters are kept by their workflow; fuzz also owns generated and
/// built case counts. Both accumulate execution fields through `Stats`' one
/// atomic checked operation, leaving those campaign counts untouched.
pub(crate) trait StepStats {
    fn add_receipt(&mut self, receipt: &Stats) -> Result<(), StatsOverflow>;
}

impl StepStats for Stats {
    fn add_receipt(&mut self, receipt: &Stats) -> Result<(), StatsOverflow> {
        self.checked_add_assign(receipt)
    }
}

impl StepStats for crate::fuzz::Stats {
    fn add_receipt(&mut self, receipt: &Stats) -> Result<(), StatsOverflow> {
        let mut total = Stats {
            packets_attempted: self.packets_attempted,
            packets_completed: self.packets_completed,
            bytes: self.bytes,
            elapsed: self.elapsed,
            capture: self.capture,
        };
        total.checked_add_assign(receipt)?;
        self.packets_attempted = total.packets_attempted;
        self.packets_completed = total.packets_completed;
        self.bytes = total.bytes;
        self.elapsed = total.elapsed;
        self.capture = total.capture;
        Ok(())
    }
}

/// Workflow vocabulary and coordinate for each failure at the boundary.
/// Validation hooks retain their own error type so sent-probe mismatches can
/// identify the particular probe rather than merely its batch.
pub(crate) trait StepErrors {
    type Error;
    fn interrupted(&self, source: Interrupted) -> Self::Error;
    fn duration(&self, source: DeadlineExceeded) -> Self::Error;
    fn execution(&self, source: BoundaryError) -> Self::Error;
    fn clock(&self, source: Box<dyn StdError + Send + Sync>) -> Self::Error;
    fn evidence(&self, message: String) -> Self::Error;
    fn overflow(&self, source: StatsOverflow) -> Self::Error;
}

pub(crate) fn execute<R, E, A, S>(
    deadline: &mut Deadline,
    executor: &mut E,
    request: &mut R,
    bounds: EvidenceBounds,
    stats: &mut S,
    errors: &A,
    validate: impl FnOnce(&R, &R::Execution) -> Result<(), A::Error>,
) -> Result<R::Execution, A::Error>
where
    R: LiveRequest,
    R::Execution: Receipt,
    E: Executor<R>,
    A: StepErrors,
    S: StepStats,
{
    deadline
        .enforce()
        .map_err(|error| errors.interrupted(error))?;
    deadline
        .start_accounting(Duration::ZERO)
        .map_err(|error| errors.duration(error))?;
    *request.timeout_mut() = deadline
        .bounded_timeout(*request.timeout_mut())
        .map_err(|error| errors.duration(error))?;
    deadline
        .enforce()
        .map_err(|error| errors.interrupted(error))?;

    let result = executor.execute(request);
    // An executor may fail at the exact moment the operation is interrupted.
    // For a returned receipt, however, validate and count confirmed traffic
    // before surfacing that interruption.
    let interrupted = deadline.enforce().err();
    let receipt = match result {
        Ok(receipt) => receipt,
        Err(source) => {
            if let Some(interrupted) = interrupted {
                return Err(errors.interrupted(interrupted));
            }
            return Err(errors.execution(source));
        }
    };
    if receipt.permit() != request.permit() {
        return Err(errors
            .evidence("executor returned evidence for a different execution permit".to_owned()));
    }
    validate_captured_evidence_limits(
        receipt.matched(),
        receipt.unsolicited(),
        receipt.unmatched(),
        receipt.undecoded(),
        bounds.frames,
        bounds.bytes,
    )
    .map_err(|error| errors.evidence(format_captured_error(error)))?;
    validate(request, &receipt)?;
    let accounted = deadline.account(receipt.stats().elapsed);
    stats
        .add_receipt(receipt.stats())
        .map_err(|error| errors.overflow(error))?;
    if let Some(interrupted) = interrupted {
        return Err(errors.interrupted(interrupted));
    }
    accounted.map_err(|error| errors.duration(error))?;
    deadline
        .enforce()
        .map_err(|error| errors.interrupted(error))?;
    Ok(receipt)
}

fn format_captured_error(error: ExchangeEvidenceError) -> String {
    super::evidence::format_exchange_evidence_error(error, "batch", "live")
}

/// Rate calculation is shared even by rolling pipelines whose waiting is
/// performed by their capture provider rather than by a sleeping clock.
pub(crate) struct Pacer;

impl Pacer {
    pub(crate) fn delay(items: usize, rate: Option<u32>) -> Option<Duration> {
        crate::clock::rate_delay(items, rate)
    }

    /// Charges both wall time and the requested delay to the operation, and
    /// enforces the *whole* deadline after sleep (including on clock failure).
    pub(crate) fn wait<C: Clock, E>(
        deadline: &mut Deadline,
        clock: &mut C,
        delay: Duration,
        interrupted: impl Fn(Interrupted) -> E,
        duration: impl Fn(DeadlineExceeded) -> E,
        clock_error: impl Fn(C::Error) -> E,
    ) -> Result<(), E> {
        deadline.enforce().map_err(&interrupted)?;
        deadline.start_accounting(delay).map_err(&duration)?;
        let slept = clock.sleep(delay);
        deadline.enforce().map_err(&interrupted)?;
        slept.map_err(clock_error)?;
        deadline.account(delay).map_err(&duration)?;
        deadline.enforce().map_err(interrupted)
    }
}

/// Adds pacing to a summary with the same checked statistics addition as a
/// receipt (without fabricating packets or capture statistics).
pub(crate) fn account_pacing<A: StepErrors, S: StepStats>(
    stats: &mut S,
    delay: Duration,
    errors: &A,
) -> Result<(), A::Error> {
    stats
        .add_receipt(&Stats {
            elapsed: delay,
            ..Stats::default()
        })
        .map_err(|error| errors.overflow(error))
}

impl<P> LiveRequest for super::runner::Batch<P> {
    fn timeout_mut(&mut self) -> &mut Duration {
        &mut self.timeout
    }
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
}

impl Receipt for super::runner::Execution {
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
    fn stats(&self) -> &Stats {
        &self.stats
    }
    fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
    fn matched(&self) -> &[crate::exchange::Response] {
        &self.responses
    }
    fn unsolicited(&self) -> &[DecodedPacket] {
        &self.unsolicited
    }
    fn undecoded(&self) -> &[Frame] {
        &self.undecoded
    }
}

impl LiveRequest for crate::scan::Batch {
    fn timeout_mut(&mut self) -> &mut Duration {
        &mut self.timeout
    }
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
}

impl LiveRequest for crate::dns::Exchange {
    fn timeout_mut(&mut self) -> &mut Duration {
        &mut self.timeout
    }
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
}

impl Receipt for crate::dns::Execution {
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
    fn stats(&self) -> &Stats {
        &self.stats
    }
    fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
    fn matched(&self) -> &[crate::exchange::Response] {
        &self.responses
    }
    fn unsolicited(&self) -> &[DecodedPacket] {
        &self.unsolicited
    }
    fn undecoded(&self) -> &[Frame] {
        &self.undecoded
    }
}

impl LiveRequest for crate::fuzz::ExecutionCase {
    fn timeout_mut(&mut self) -> &mut Duration {
        &mut self.timeout
    }
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
}

impl Receipt for crate::fuzz::Execution {
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
    fn stats(&self) -> &Stats {
        &self.stats
    }
    fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
    fn matched(&self) -> &[crate::exchange::Response] {
        &self.responses
    }
    fn unmatched(&self) -> &[Frame] {
        &self.unmatched
    }
    fn undecoded(&self) -> &[Frame] {
        &self.undecoded
    }
}

#[cfg(test)]
mod tests;
