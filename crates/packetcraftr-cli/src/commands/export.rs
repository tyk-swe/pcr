// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `export`: saves selected conversations and datagrams with the physical
//! frames they depend on.

pub(super) mod arguments;
mod rendering;

use self::arguments::Args;
use crate::output::{
    self,
    contract::{Command, ToolFormat},
};
use crate::{
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate},
};
use packetcraftr_core::{analysis, capture_file};

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(self.limits.duration.max_duration())
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
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(crate) fn run(args: Args, format: ToolFormat, stream: &StreamEncoder) -> Result<(), CliError> {
    let setup =
        super::offline_analysis::prepare(args.limits, args.filter.as_deref(), &args.decode)?;
    let selection = analysis::export::Selection {
        streams: args.streams,
        datagram_frames: args.datagram_frames,
        filter: setup.filter.as_ref(),
        max_selected_frames: args.max_selected_frames,
    };
    selection.validate().map_err(CliError::classified)?;
    let mut staged = crate::staged_output::StagedFile::stage(&args.write)?;
    let limits = capture_file::Limits {
        max_frames: args.limits.capture.max_frames,
        max_bytes: args.limits.capture.max_bytes,
    };
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
    let report = output::export::Report::new(args.write.display().to_string(), report, plan)
        .map_err(CliError::classified)?;
    staged.sync()?;
    crate::cancellation::check()?;
    staged.persist()?;
    match format {
        ToolFormat::Json => emit_aggregate(Command::Export, report, Vec::new()),
        ToolFormat::Ndjson => stream.complete(report, Vec::new()).map_err(Into::into),
        ToolFormat::Text => rendering::render_text(&report),
    }
}
