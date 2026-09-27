// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! A declared predicate over the findings and frame coverage of a completed
//! expert analysis.
//!
//! A [`Gate`] observes every [`Finding`] the analysis produces — before any
//! report selector — counts each event once, and counts the events at or
//! above [`Options::min_severity`] as triggering. [`Gate::finish`] then
//! evaluates the completed run's matched physical-frame count, in priority
//! order: an observed violation wins over insufficient coverage, and
//! equality with either criterion passes.
//!
//! A passing gate establishes only the declared predicate over the selected
//! evidence, not the health or completeness of the observed network. Gate
//! state is constant-size: findings are counted, never retained.

use serde::Serialize;

use crate::diagnostic::Severity;
use crate::error::{Classification, Classified, Kind};

use super::Finding;

/// The criteria a [`Gate`] evaluates a completed analysis against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Findings of at least this severity count as triggering: `Warning`
    /// includes warnings and errors, `Info` includes every finding.
    pub min_severity: Severity,
    /// How many triggering findings may pass. Any value is valid.
    pub allow_findings: u64,
    /// Matched physical frames the analysis must cover; at least one.
    pub minimum_frames: u64,
}

/// The verdict a completed analysis earns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Triggering findings stayed within the allowance and matched coverage
    /// met the minimum.
    Pass,
    /// Triggering findings exceeded the declared allowance.
    Fail,
    /// No violation was observed, but matched coverage fell short of the
    /// declared minimum, so the predicate cannot answer.
    Inconclusive,
}

/// Why the verdict was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Every criterion held.
    WithinAllowance,
    /// Triggering findings exceeded `allow_findings`.
    FindingAllowanceExceeded,
    /// `frames_matched` fell below `minimum_frames` without a violation.
    InsufficientFrames,
}

/// The gate's evaluation of one completed analysis, echoing the configured
/// criteria beside the counters that decided them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub verdict: Verdict,
    pub reason: Reason,
    /// The configured triggering threshold.
    pub min_severity: Severity,
    /// The configured triggering-finding allowance.
    pub allow_findings: u64,
    /// The configured minimum matched-frame coverage.
    pub minimum_frames: u64,
    /// The completed run's matched physical-frame count.
    pub frames_matched: u64,
    /// Every finding event the gate observed.
    pub findings_observed: u64,
    /// Observed findings at or above `min_severity`; at most
    /// `findings_observed`.
    pub triggering_findings: u64,
}

/// Counts observed findings against the declared criteria.
///
/// The gate sees every finding produced by the selected analysis, including
/// the trailing events a collector emits only when the pass finishes;
/// `finish` is called only for a completed analysis and cannot reinterpret
/// a failed run as a verdict.
#[derive(Debug)]
pub struct Gate {
    options: Options,
    findings_observed: u64,
    triggering_findings: u64,
}

impl Gate {
    /// Validates the declared criteria: `minimum_frames` must be non-zero.
    pub fn new(options: Options) -> Result<Self, Error> {
        if options.minimum_frames == 0 {
            return Err(Error::InvalidMinimum {
                value: options.minimum_frames,
            });
        }
        Ok(Self {
            options,
            findings_observed: 0,
            triggering_findings: 0,
        })
    }

    /// Counts one produced finding: `findings_observed` once per event, and
    /// `triggering_findings` when its severity is at least
    /// `min_severity`. Several findings from one physical frame count
    /// individually.
    pub fn observe(&mut self, finding: &Finding) -> Result<(), Error> {
        self.findings_observed = self
            .findings_observed
            .checked_add(1)
            .ok_or(Error::Overflow {
                counter: "findings_observed",
            })?;
        if finding.severity >= self.options.min_severity {
            self.triggering_findings =
                self.triggering_findings
                    .checked_add(1)
                    .ok_or(Error::Overflow {
                        counter: "triggering_findings",
                    })?;
        }
        Ok(())
    }

    /// Evaluates the completed analysis over its matched physical-frame
    /// count. A violation wins over insufficient coverage; equality with
    /// the allowance and the coverage minimum passes.
    pub fn finish(self, frames_matched: u64) -> Report {
        let (verdict, reason) = if self.triggering_findings > self.options.allow_findings {
            (Verdict::Fail, Reason::FindingAllowanceExceeded)
        } else if frames_matched < self.options.minimum_frames {
            (Verdict::Inconclusive, Reason::InsufficientFrames)
        } else {
            (Verdict::Pass, Reason::WithinAllowance)
        };
        Report {
            verdict,
            reason,
            min_severity: self.options.min_severity,
            allow_findings: self.options.allow_findings,
            minimum_frames: self.options.minimum_frames,
            frames_matched,
            findings_observed: self.findings_observed,
            triggering_findings: self.triggering_findings,
        }
    }
}

/// Gate construction and counting failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A gate requires positive matched-frame coverage.
    #[error("invalid expert gate minimum_frames={value}: must be non-zero")]
    InvalidMinimum { value: u64 },
    /// Bounded analysis cannot drive a counter this far; a checked
    /// increment fails closed rather than wrapping.
    #[error("expert gate {counter} counter overflowed")]
    Overflow { counter: &'static str },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidMinimum { .. } => Classification::new(
                "cli.expert_gate",
                Kind::Usage,
                Some("declare a positive minimum matched-frame count"),
            ),
            Self::Overflow { .. } => Classification::new(
                "policy.expert_gate_limit",
                Kind::Policy,
                Some("reduce the finding volume the analysis produces; a gate counter cannot wrap"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Options {
        Options {
            min_severity: Severity::Info,
            allow_findings: 0,
            minimum_frames: 1,
        }
    }

    fn finding() -> Finding {
        Finding {
            severity: Severity::Info,
            code: "test.finding",
            number: 1,
            stream: None,
            message: "fixture".to_owned(),
        }
    }

    #[test]
    fn checked_counters_fail_closed_instead_of_wrapping() {
        // Reachable only through state no bounded analysis can produce, so
        // the test builds it through the module's own field access.
        let mut gate = Gate {
            options: options(),
            findings_observed: u64::MAX,
            triggering_findings: 0,
        };
        let error = gate.observe(&finding()).expect_err("counter must not wrap");
        assert!(matches!(
            error,
            Error::Overflow {
                counter: "findings_observed"
            }
        ));
        let classification = error.classification();
        assert_eq!(classification.code, "policy.expert_gate_limit");
        assert_eq!(classification.kind, Kind::Policy);

        let mut gate = Gate {
            options: options(),
            findings_observed: 0,
            triggering_findings: u64::MAX,
        };
        let error = gate.observe(&finding()).expect_err("counter must not wrap");
        assert!(matches!(
            error,
            Error::Overflow {
                counter: "triggering_findings"
            }
        ));
    }
}
