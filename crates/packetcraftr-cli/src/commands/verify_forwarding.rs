// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use std::path::Path;

use crate::output::contract::ToolFormat;
use packetcraftr_core::analysis::{self, forwarding};
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::filter::Filter;

use self::arguments::Args;
use super::CommandExit;
use super::offline_analysis::{self, AnalysisSetup};
use crate::command_options::CaptureReaderBoundsArgs;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::open_capture_hashed;
use crate::output::verify_forwarding::CaptureSource;
use crate::rendering::StreamEncoder;

/// The process status when the comparison completed and published its report
/// but the verdict was not `pass`. `fail` and `inconclusive` share this code;
/// the report's `verdict` field distinguishes them.
const VERDICT_NOT_PASS: u8 = 1;

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_field_bytes: Bytes @ ObservationCollection preset(16384, 65536),
            max_evidence_bytes: Bytes @ ObservationCollection preset(8388608, 67108864),
            max_details: Count @ ResultRetention preset(64, 256),
            max_detail_bytes: Bytes @ ResultRetention preset(1048576, 4194304),
            max_scratch_bytes: Bytes @ Comparison preset(16777216, 134217728),
        ]);
        // Indexing runs only when the compiled rules or filters need the stream
        // index, which `run` reports once they compile.
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages {
                tcp: false,
                index: crate::resources::Enabled::StreamIndex,
                provenance: false,
            },
        );
    }

    fn run(
        self,
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream)
    }
}

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
                Kind::Usage,
                Some("pipe one capture to stdin and name the other's path"),
            ),
            "ingress and egress cannot both read stdin",
            Vec::new(),
        ));
    }
    let prepared = offline_analysis::prepare(arguments.limits, None, &arguments.decode)?;
    // Rules and selection filters compile before either capture is opened,
    // so a malformed declaration never reads input.
    let rules = forwarding::Rules::compile_declarations(
        forwarding::Declarations {
            identity: &arguments.identity,
            preserve: &arguments.preserve,
            preserve_presence: &arguments.preserve_presence,
            expect: &arguments.expect,
            expect_absent: &arguments.expect_absent,
        },
        &prepared.registry,
        arguments.max_field_bytes,
    )
    .map_err(CliError::classified)?;
    let ingress_filter = compile_selection(arguments.ingress_filter.as_deref(), &prepared)?;
    let egress_filter = compile_selection(arguments.egress_filter.as_deref(), &prepared)?;
    crate::resources::stream_index_needed(
        rules.requirements().stream_index
            || [&ingress_filter, &egress_filter]
                .into_iter()
                .flatten()
                .any(|filter| filter.requirements().stream_index),
    );

    let (ingress, ingress_source) = collect(
        &prepared,
        &arguments.ingress,
        arguments.limits.capture.reader,
        forwarding::Side::Ingress,
        ingress_filter.as_ref(),
        &rules,
        arguments.max_evidence_bytes,
    )?;
    let (egress, egress_source) = collect(
        &prepared,
        &arguments.egress,
        arguments.limits.capture.reader,
        forwarding::Side::Egress,
        egress_filter.as_ref(),
        &rules,
        arguments.max_evidence_bytes,
    )?;
    let deadline = crate::invocation::deadline();
    let report = forwarding::verify_with_limits(
        &rules,
        ingress,
        egress,
        forwarding::VerifyLimits {
            max_details: arguments.max_details,
            max_detail_bytes: arguments.max_detail_bytes,
            max_scratch_bytes: arguments.max_scratch_bytes,
        },
        Some(crate::cancellation::signal()),
        deadline.as_deref(),
    )
    .map_err(CliError::classified)?;
    let exit = match report.verdict {
        forwarding::Verdict::Pass => CommandExit::SUCCESS,
        forwarding::Verdict::Fail | forwarding::Verdict::Inconclusive => {
            CommandExit::status(VERDICT_NOT_PASS)
        }
    };
    rendering::render(
        format,
        stream,
        &report,
        &arguments,
        forwarding::Sided {
            ingress: ingress_source,
            egress: egress_source,
        },
    )?;
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
) -> Result<(forwarding::SideInput, CaptureSource), CliError> {
    let (mut reader, fingerprint) = open_capture_hashed(path, bounds)?;
    // Select physical packets in the callback: pipeline filters also see
    // reconstructed datagrams, whose provenance this report cannot represent.
    let mut options = prepared.options();
    let mut requirements = rules.requirements();
    if let Some(filter) = filter {
        let next = filter.requirements();
        requirements.stream_index |= next.stream_index;
        requirements.tcp_stream |= next.tcp_stream;
        requirements.udp_stream |= next.udp_stream;
        requirements.timestamp |= next.timestamp;
    }
    options.plan = analysis::Plan::physical(requirements);
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
    crate::cancellation::check()?;
    Ok((
        forwarding::SideInput {
            frames_read: summary.frames_read,
            observations: collector.into_observations(),
        },
        fingerprint.finish(),
    ))
}
