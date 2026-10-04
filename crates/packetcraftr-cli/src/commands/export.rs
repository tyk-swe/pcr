// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use self::arguments::Args;
use crate::output::{
    self,
    contract::{Command, Format},
};
use crate::{
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate},
};
use packetcraftr_core::{analysis, capture_file};

impl super::Spec for Args {
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
        format: Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(crate) fn run(args: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    let streams = args
        .streams
        .iter()
        .map(crate::command_options::Selector::get)
        .collect::<Result<Vec<_>, _>>()?;
    let setup =
        super::offline_analysis::prepare(args.limits, args.filter.as_deref(), &args.decode)?;
    let selection = analysis::export::Selection {
        streams,
        datagram_frames: args.datagram_frames,
        filter: setup.filter.as_ref(),
        max_selected_frames: args.max_selected_frames,
    };
    selection.validate().map_err(CliError::classified)?;
    let mut staged = crate::staged_output::StagedFile::stage(&args.write)?;
    let limits = args.limits.capture.stream_limits();
    let mut source = crate::input::open_capture(&args.path, args.limits.capture.reader)?;
    let mut reader =
        crate::input::snapshot_capture(&mut source, args.limits.capture.reader, limits)?;
    let plan = analysis::export::plan(
        &mut reader,
        setup.registry.clone(),
        &setup.options(),
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
    crate::cancellation::check()?;
    staged.persist()?;
    match format {
        Format::Json => emit_aggregate(Command::Export, report, Vec::new()),
        Format::Ndjson => stream.complete(report, Vec::new()).map_err(Into::into),
        Format::Text => rendering::render_text(&report),
        other => other.unreachable(),
    }
}
