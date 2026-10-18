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
pub(super) struct Bounds {
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
    pub(super) max_result_bytes: usize,
    /// Exit 1 when a finding meets or exceeds this severity.
    #[arg(long, value_enum)]
    pub(super) fail_on: Option<SeverityArg>,
}
impl Bounds {
    pub(super) fn core(self) -> Result<security::Limits, CliError> {
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
    pub(super) fn resources(&self, settings: &mut Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_findings: Count @ ResultRetention preset(256, 4096),
            max_groups: Count @ ActiveState preset(256, 4096),
            max_observations: Count @ ActiveState preset(10000, 100000),
            max_result_bytes: Bytes @ ResultRetention preset(2097152, 16777216),
        ]);
    }
}
