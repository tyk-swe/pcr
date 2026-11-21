// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr::differential as lib;
use packetcraftr_core::error::Kind;

use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::output;
use crate::output::contract::Format;

use super::rendering;

pub(crate) const AFTER_LONG_HELP: &str = r"Finalize a provisional (spoofed) differential Campaign offline. Reads the Campaign aggregate JSON published by `network differential --output json` or a previous `network differential-join --output json` and the Responder reception log written by `network differential-responder --log-file`, answers every attempt whose Variant, attempt sequence, and payload digest all match a reception record, and republishes the matrix. Reply frames stay in the original Campaign report. The joined report carries Verdicts and attempt identities.

With --sensor-capture (text output only), exact Canary probes found in a third capture are classified against Responder delivery for every Variant, separating delivered traffic the sensor missed from probes the sensor saw that never arrived. A sensor observation counts only when its Variant, attempt sequence, and exact payload digest all match and its source tuple matches the Campaign source port and spoofed source when one was planned.

Examples:
  packetcraftr network differential-join campaign.json --responder-log responder-log.jsonl
  packetcraftr network differential-join campaign.json --responder-log responder-log.jsonl --sensor-capture sensor.pcapng";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Campaign aggregate JSON from a differential run.
    pub(crate) campaign: PathBuf,
    /// Responder reception log in JSON lines.
    #[arg(long)]
    pub(crate) responder_log: PathBuf,
    /// Third-vantage sensor PCAP or PCAPNG capture to classify against
    /// Responder delivery. Text output only.
    #[arg(long)]
    pub(crate) sensor_capture: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
}

use crate::output::contract::PublishedType;

impl crate::commands::Spec for Args {
    const PUBLISHED: &'static [PublishedType] = &[PublishedType {
        definition: "differentialJoinSuccess",
        command: "differential-join",
        rust_types: &["crate::commands::network::differential::output::Report"],
        events: &[],
        example: "examples/documents/output-differential-join-success.json",
    }];
    const FORMATS: &'static [Format] = crate::output::contract::TEXT_JSON;
    const OFFLINE: bool = true;

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

fn run(invocation: &crate::invocation::Invocation, arguments: Args) -> Result<(), CliError> {
    if arguments.sensor_capture.is_some() && invocation.format != Format::Text {
        return Err(CliError::new(
            Kind::Usage,
            format!(
                "--sensor-capture prints text only, not --output {}",
                invocation.format
            ),
        ));
    }
    let stdin = std::path::Path::new("-");
    let stdin_sources = [&arguments.campaign, &arguments.responder_log]
        .into_iter()
        .chain(arguments.sensor_capture.iter())
        .filter(|path| *path == stdin)
        .count();
    if stdin_sources > 1 {
        return Err(CliError::new(
            Kind::Usage,
            "stdin may serve at most one differential-join input",
        ));
    }
    let sensor = arguments
        .sensor_capture
        .as_deref()
        .map(|path| super::sensor::read_sensor_capture(invocation, path, arguments.limits))
        .transpose()?;
    let inputs = super::campaign::load(invocation, &arguments.campaign, &arguments.responder_log)?;
    let joined = lib::join_receptions(inputs.campaign, &inputs.receptions);
    let vantage = sensor.as_ref().map(|sensor| {
        (
            sensor.frames,
            sensor.observations.len(),
            lib::three_vantage(&joined, &sensor.observations),
        )
    });
    invocation.check()?;
    let published = output::envelope::Published::<super::output::Report>::try_from(joined)
        .map_err(CliError::classified)?;
    match invocation.format {
        Format::Text => {
            rendering::render_report_text(invocation, &published.result)?;
            if let Some((frames, probes_seen, rows)) = &vantage {
                rendering::render_vantage_text(invocation, *frames, *probes_seen, rows)?;
            }
            Ok(())
        }
        Format::Json => crate::publication::emit_published(
            invocation,
            output::contract::Command::DifferentialJoin,
            published,
        ),
        other => other.unreachable(),
    }
}
