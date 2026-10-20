// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::invalid;
use crate::{errors::CliError, resources::Settings};
use clap::{Args, ValueEnum};
use packetcraftr_core::security::{self, Severity};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(super) enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Info => Self::Info,
            SeverityArg::Low => Self::Low,
            SeverityArg::Medium => Self::Medium,
            SeverityArg::High => Self::High,
            SeverityArg::Critical => Self::Critical,
        }
    }
}
#[derive(Clone, Copy, Debug, Args)]
pub(in crate::commands) struct Bounds {
    /// Maximum retained security findings.
    #[arg(long, default_value_t = 4096)]
    pub(super) max_findings: usize,
    /// Maximum distinct security groups or compared endpoints.
    #[arg(long, default_value_t = 4096)]
    pub(super) max_groups: usize,
    /// Maximum retained analysis observations.
    #[arg(long, default_value_t = 100_000)]
    pub(super) max_observations: usize,
    /// Maximum serialized result bytes, in every output format.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub(in crate::commands) max_result_bytes: usize,
    /// Exit 1 when a finding meets or exceeds this severity.
    #[arg(long, value_enum)]
    pub(super) fail_on: Option<SeverityArg>,
    /// Exit 1 after publishing when report or finding evidence is incomplete.
    #[arg(long)]
    pub(super) fail_incomplete: bool,
}
impl Bounds {
    pub(super) fn fails(&self, report: &security::Report) -> bool {
        report.meets(self.fail_on.map(Into::into))
            || (self.fail_incomplete
                && (!report.completeness.complete
                    || report.findings.iter().any(|finding| !finding.complete)))
    }

    pub(in crate::commands) fn core(self) -> Result<security::Limits, CliError> {
        let limits = security::Limits {
            max_findings: self.max_findings,
            max_groups: self.max_groups,
            max_observations: self.max_observations,
        };
        limits.validate().map_err(CliError::classified)?;
        if self.max_result_bytes == 0 || self.max_result_bytes > 256 * 1024 * 1024 {
            return Err(invalid("max-result-bytes must be in 1..=268435456"));
        }
        Ok(limits)
    }
    pub(in crate::commands) fn resources(&self, settings: &mut Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_findings: Count @ ResultRetention preset(256, 4096),
            max_groups: Count @ ActiveState preset(256, 4096),
            max_observations: Count @ ActiveState preset(10000, 100000),
            max_result_bytes: Bytes @ ResultRetention preset(2097152, 16777216),
        ]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestArgs {
        #[command(flatten)]
        bounds: Bounds,
    }

    #[test]
    fn completion_and_severity_gates_are_opt_in_and_combine() {
        let defaults = TestArgs::parse_from(["security"]).bounds;
        let gate = TestArgs::parse_from(["security", "--fail-incomplete"]).bounds;
        let both =
            TestArgs::parse_from(["security", "--fail-incomplete", "--fail-on", "high"]).bounds;
        let mut report = security::Report::new("hunt");
        assert!(!gate.fails(&report));
        report.completeness.note("partial capture");
        assert!(!defaults.fails(&report));
        assert!(gate.fails(&report));
        report.completeness = security::Completeness::observed();
        report.findings.push(security::Finding::new(
            "test",
            Severity::High,
            "host",
            "summary",
            serde_json::Value::Null,
            "review",
        ));
        assert!(!gate.fails(&report));
        assert!(both.fails(&report));
        report.findings[0].severity = Severity::Low;
        assert!(!both.fails(&report));
        report.findings[0].complete = false;
        assert!(gate.fails(&report));
        assert!(both.fails(&report));
    }
}
