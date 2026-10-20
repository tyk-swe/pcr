// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;

use self::arguments::Args;
use crate::output::{
    self,
    contract::{Command, Format},
};
use crate::{
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate, write_summary_line},
};
use packetcraftr_core::{analysis, capture_file};

impl crate::commands::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
    ];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_selected_frames: Count @ Operation]);
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages::with_tcp(false),
        );
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        let format = invocation.format;
        let stream = &invocation.output;
        run(invocation, self, format, stream).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(crate) fn run(
    invocation: &crate::invocation::Invocation,
    args: Args,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let streams = args
        .streams
        .iter()
        .map(crate::command_options::Selector::get)
        .collect::<Result<Vec<_>, _>>()?;
    let setup = crate::commands::offline_analysis::prepare(
        args.limits,
        args.filter.as_deref(),
        &args.decode,
    )?;
    let selection = analysis::export::Selection {
        streams,
        datagram_frames: args.datagram_frames,
        filter: setup.filter.as_ref(),
        max_selected_frames: args.max_selected_frames,
    };
    selection.validate().map_err(CliError::classified)?;
    let mut staged = crate::staged_output::StagedFile::stage(invocation, &args.write)?;
    let limits = args.limits.capture.stream_limits();
    let mut source =
        crate::input::open_capture(invocation, &args.path, args.limits.capture.reader)?;
    let mut reader = crate::input::snapshot_capture(
        invocation,
        &mut source,
        args.limits.capture.reader,
        limits,
    )?;
    let plan = analysis::export::plan(
        &mut reader,
        setup.registry.clone(),
        &setup.options(invocation),
        &selection,
    )
    .map_err(CliError::classified)?;
    reader.rewind().map_err(CliError::classified)?;
    let (writer, report) = capture_file::select(
        &mut reader,
        args.compression
            .for_file()
            .writer(std::io::BufWriter::with_capacity(
                64 * 1024,
                staged.as_file_mut(),
            ))?,
        limits,
        |number, _| Ok(plan.source_frames.contains(&number)),
    )
    .map_err(CliError::classified)?;
    let _ = writer.finish().map_err(CliError::classified)?;
    // Construct all fallible report fields before publishing the saved capture.
    let report = output::export::Report::try_from((args.write.display().to_string(), report, plan))
        .map_err(CliError::classified)?;
    staged.sync()?;
    invocation.check()?;
    staged.persist()?;
    match format {
        Format::Json => emit_aggregate(invocation, Command::Export, report, Vec::new()),
        Format::Ndjson => stream.complete(report, Vec::new()).map_err(Into::into),
        Format::Text => {
            for selected in &report.matched_streams {
                crate::rendering::write_stdout_line(
                    invocation,
                    format_args!(
                        "exported stream: {}:{}",
                        selected.transport.as_str(),
                        selected.index
                    ),
                )?;
            }
            for missing in &report.unmatched_streams {
                crate::rendering::write_stdout_line(
                    invocation,
                    format_args!(
                        "warning: unmatched stream {}:{}",
                        missing.transport.as_str(),
                        missing.index
                    ),
                )?;
            }
            for missing in &report.unmatched_datagram_frames {
                crate::rendering::write_stdout_line(
                    invocation,
                    format_args!("warning: unmatched datagram frame {missing}"),
                )?;
            }
            for incomplete in &report.selected_incomplete_datagrams {
                crate::rendering::write_stdout_line(
                    invocation,
                    format_args!("warning: incomplete datagram {:?}", incomplete.key),
                )?;
            }
            if report.source_outcomes_omitted > 0 {
                crate::rendering::write_stdout_line(
                    invocation,
                    format_args!("{} source outcomes omitted", report.source_outcomes_omitted),
                )?;
            }
            stream
                .presentation()
                .details(invocation, "Export sources", &report)?;
            write_summary_line(
                invocation,
                format_args!(
                    "exported {} of {} physical frames to {}; {} complete and {} incomplete datagrams, {} unmatched stream selectors, {} unmatched datagram selectors",
                    report.capture.frames_selected,
                    report.capture.frames_read,
                    report.path,
                    report.selected_complete_datagrams,
                    report.selected_incomplete_datagrams.len(),
                    report.unmatched_streams.len(),
                    report.unmatched_datagram_frames.len()
                ),
            )
        }
        other => other.unreachable(),
    }
}
