// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::commands::security::{Bounds, input, publish, read, source};
use crate::commands::{CommandExit, Spec};
use crate::invocation::Invocation;
use crate::output::contract::{Command, Format};
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
        input::validate_stdin_sources([self.before.as_path(), self.after.as_path()])?;
        let limits = self.bounds.core()?;
        let a = read(&self.before, security::scan::MAX_INPUT_BYTES)?;
        i.check()?;
        let b = read(&self.after, security::scan::MAX_INPUT_BYTES)?;
        i.check()?;
        let mut result = security::scan::compare(&a, &b, limits).map_err(CliError::classified)?;
        result.sources = vec![source(&self.before, &a), source(&self.after, &b)];
        publish(i, Command::ScanDiff, result, self.bounds)
    }
}
