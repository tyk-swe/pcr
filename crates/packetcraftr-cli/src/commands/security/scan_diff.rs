// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Bounds, Command, CommandExit, Format, Invocation, Spec, publish, read};
use crate::{errors::CliError, resources::Settings};
use clap::Args;
use packetcraftr_core::security;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub(crate) struct ScanDiff {
    /// Earlier scan's aggregate JSON; - reads redirected stdin (one input only).
    before: PathBuf,
    /// Later scan's aggregate JSON; - reads redirected stdin (one input only).
    after: PathBuf,
    #[command(flatten)]
    bounds: Bounds,
}
impl Spec for ScanDiff {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;
    fn resources(&self, s: &mut Settings<'_>) {
        self.bounds.resources(s);
    }
    fn run(self, i: &Invocation) -> Result<CommandExit, CliError> {
        super::input::validate_stdin_sources([self.before.as_path(), self.after.as_path()])?;
        let limits = self.bounds.core()?;
        let a = read(&self.before, security::scan::MAX_INPUT_BYTES)?;
        i.check()?;
        let b = read(&self.after, security::scan::MAX_INPUT_BYTES)?;
        i.check()?;
        let before = super::scan_input::parse(&a, limits).map_err(CliError::classified)?;
        let after = super::scan_input::parse(&b, limits).map_err(CliError::classified)?;
        let mut result = security::scan::compare_snapshots(&before, &after, limits)
            .map_err(CliError::classified)?;
        result.sources = vec![
            super::source(&self.before, &a),
            super::source(&self.after, &b),
        ];
        publish(i, Command::ScanDiff, result, self.bounds)
    }
}
