// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr::differential as lib;

use crate::errors::CliError;
use crate::output;
use crate::output::contract::Format;

use super::rendering;

pub(crate) const AFTER_LONG_HELP: &str = r"Finalize a provisional (spoofed) differential Campaign offline. Reads the Campaign aggregate JSON published by `network differential --output json` or a previous `network differential-join --output json` and the Responder reception log written by `network differential-responder --log-file`, answers every attempt whose Variant, attempt sequence, and payload digest all match a reception record, and republishes the matrix. Reply frames stay in the original Campaign report. The joined report carries Verdicts and attempt identities.

Example:
  packetcraftr network differential-join campaign.json --responder-log responder-log.jsonl";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Campaign aggregate JSON from a differential run.
    pub(crate) campaign: PathBuf,
    /// Responder reception log in JSON lines.
    #[arg(long)]
    pub(crate) responder_log: PathBuf,
}

impl crate::commands::Spec for Args {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

fn run(invocation: &crate::invocation::Invocation, arguments: Args) -> Result<(), CliError> {
    let inputs = super::campaign::load(invocation, &arguments.campaign, &arguments.responder_log)?;
    let joined = lib::join_receptions(inputs.campaign, &inputs.receptions);
    invocation.check()?;
    let published = output::envelope::Published::<
        crate::commands::network::differential::output::Report,
    >::try_from(joined)
    .map_err(CliError::classified)?;
    match invocation.format {
        Format::Text => rendering::render_report_text(invocation, &published.result),
        Format::Json => crate::rendering::emit_published(
            invocation,
            output::contract::Command::DifferentialJoin,
            published,
        ),
        other => other.unreachable(),
    }
}
