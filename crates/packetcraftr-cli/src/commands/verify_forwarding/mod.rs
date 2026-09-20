// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use std::path::Path;

use packetcraftr_cli::output::contract::ToolFormat;
use packetcraftr_core::analysis::{self, forwarding};
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::filter::Filter;

use self::arguments::Args;
use super::CommandExit;
use super::offline_analysis::{self, AnalysisSetup};
use crate::command_options::CaptureReaderBoundsArgs;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::open_capture;
use crate::rendering::StreamEncoder;

/// The process status when the comparison completed and published its report
/// but the verdict was not `pass`. `fail` and `inconclusive` share this code;
/// the report's `verdict` field distinguishes them.
const VERDICT_NOT_PASS: u8 = 1;

pub(super) fn run(
    arguments: Args,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<CommandExit, CliError> {
    let stdin = Path::new("-");
    if arguments.ingress == stdin && arguments.egress == stdin {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.input_source",
                Kind::Cli,
                Some("pipe one capture to stdin and name the other's path"),
            ),
            "ingress and egress cannot both read stdin",
            Vec::new(),
        ));
    }
    let prepared = offline_analysis::prepare(arguments.limits, None, &arguments.decode)?;
    // Rules and selection filters compile before either capture is opened,
    // so a malformed declaration never reads input.
    let rules = forwarding::Rules::compile(
        &arguments.identity,
        &arguments.preserve,
        &arguments.expect,
        &prepared.registry,
        arguments.max_field_bytes,
    )
    .map_err(CliError::classified)?;
    let ingress_filter = compile_selection(arguments.ingress_filter.as_deref(), &prepared)?;
    let egress_filter = compile_selection(arguments.egress_filter.as_deref(), &prepared)?;

    let ingress = collect(
        &prepared,
        &arguments.ingress,
        arguments.limits.capture.reader,
        forwarding::Side::Ingress,
        ingress_filter.as_ref(),
        &rules,
        arguments.max_evidence_bytes,
    )?;
    let egress = collect(
        &prepared,
        &arguments.egress,
        arguments.limits.capture.reader,
        forwarding::Side::Egress,
        egress_filter.as_ref(),
        &rules,
        arguments.max_evidence_bytes,
    )?;
    let report = forwarding::verify(
        &rules,
        ingress,
        egress,
        arguments.max_details,
        Some(crate::cancellation::signal()),
    )
    .map_err(CliError::classified)?;
    let exit = match report.verdict {
        forwarding::Verdict::Pass => CommandExit::SUCCESS,
        forwarding::Verdict::Fail | forwarding::Verdict::Inconclusive => {
            CommandExit::status(VERDICT_NOT_PASS)
        }
    };
    rendering::render(format, stream, &report, &arguments)?;
    Ok(exit)
}

/// Compiles one side's selection filter; absent selects every frame.
fn compile_selection(
    source: Option<&str>,
    prepared: &AnalysisSetup,
) -> Result<Option<Filter>, CliError> {
    source
        .map(|source| {
            filtering::compile(source, &prepared.registry, Capabilities::stream_capable())
        })
        .transpose()
}

/// Reads one capture through the shared bounded pipeline and collects the
/// observations its own selection keeps.
fn collect(
    prepared: &AnalysisSetup,
    path: &Path,
    bounds: CaptureReaderBoundsArgs,
    side: forwarding::Side,
    filter: Option<&Filter>,
    rules: &forwarding::Rules,
    max_evidence_bytes: usize,
) -> Result<forwarding::SideInput, CliError> {
    let mut reader = open_capture(path, bounds)?;
    // Select physical packets in the callback: pipeline filters also see
    // reconstructed datagrams, whose provenance this report cannot represent.
    let options = prepared.options(false);
    let mut collector = forwarding::Collector::new(rules, side, max_evidence_bytes);
    let summary = analysis::run(&mut reader, prepared.registry.clone(), &options, |record| {
        if let Some(filter) = filter
            && !filter
                .matches(&record.physical_context())
                .map_err(|error| CliError::classified(error).into_boundary_error())?
        {
            return Ok(());
        }
        collector
            .observe(&record)
            .map_err(|error| CliError::classified(error).into_boundary_error())
    })
    .map_err(CliError::classified)?;
    Ok(forwarding::SideInput {
        frames_read: summary.frames_read,
        observations: collector.into_observations(),
    })
}
