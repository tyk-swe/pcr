// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
pub(in crate::commands) mod output;

use self::arguments::Args;
use crate::output::contract::Command;
use crate::{errors::CliError, terminal::write_summary_line};
use packetcraftr_core::{analysis, capture_file};

use crate::output::contract::PublishedType;

impl crate::commands::Spec for Args {
    const PUBLISHED: &'static [PublishedType] = &[
        PublishedType {
            definition: "exportSuccess",
            command: "export",
            rust_types: &["crate::commands::files::export::output::Report"],
            events: &[],
            example: "examples/documents/output-export-complete.json",
        },
        PublishedType {
            definition: "exportStreamSuccess",
            command: "export",
            rust_types: &["crate::commands::files::export::output::Report"],
            events: &["complete"],
            example: "examples/documents/output-export-complete.json",
        },
    ];
    const FORMATS: &'static [crate::output::contract::Format] =
        crate::output::contract::TEXT_JSON_NDJSON;
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
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(crate) fn run(invocation: &crate::invocation::Invocation, args: Args) -> Result<(), CliError> {
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
    let limits = setup.capture_limits.stream_limits();
    let mut source = crate::input::open_capture(
        &invocation.control,
        &invocation.output,
        &args.path,
        setup.capture_limits,
    )?;
    let mut reader = crate::input::snapshot_capture(
        &invocation.control,
        &mut source,
        setup.capture_limits,
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
    let report = output::Report::try_from((args.write.display().to_string(), report, plan))
        .map_err(CliError::classified)?;
    staged.sync()?;
    staged.persist()?;
    crate::commands::offline_analysis::complete_application(
        invocation,
        Command::Export,
        report,
        |report| report,
        |invocation, report| {
            for selected in &report.matched_streams {
                crate::terminal::write_stdout_line(
                    invocation,
                    format_args!(
                        "exported stream: {}:{}",
                        selected.transport.as_str(),
                        selected.index
                    ),
                )?;
            }
            for missing in &report.unmatched_streams {
                crate::terminal::write_stdout_line(
                    invocation,
                    format_args!(
                        "warning: unmatched stream {}:{}",
                        missing.transport.as_str(),
                        missing.index
                    ),
                )?;
            }
            for missing in &report.unmatched_datagram_frames {
                crate::terminal::write_warning(
                    invocation,
                    format_args!("unmatched datagram frame {missing}"),
                )?;
            }
            for incomplete in &report.selected_incomplete_datagrams {
                crate::terminal::write_warning(
                    invocation,
                    format_args!("incomplete datagram {:?}", incomplete.key),
                )?;
            }
            if report.source_outcomes_omitted > 0 {
                crate::terminal::write_stdout_line(
                    invocation,
                    format_args!("{} source outcomes omitted", report.source_outcomes_omitted),
                )?;
            }
            crate::terminal::write_details(
                invocation,
                invocation.output.presentation(),
                "Export sources",
                report,
            )?;
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
        },
    )
}
