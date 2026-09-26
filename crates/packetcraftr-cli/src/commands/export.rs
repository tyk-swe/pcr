// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::output::{
    self,
    contract::{Command, ToolFormat},
};
use crate::{
    command_options::{Compression, DecodeArgs, OfflineLimitsArgs},
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate, write_plain_line},
};
use packetcraftr_core::{analysis, capture_file};
use std::path::PathBuf;
#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Source PCAP/PCAPNG; - reads redirected stdin. Compression is detected.
    pub(crate) path: PathBuf,
    /// New destination, preserving the source capture format and metadata.
    #[arg(long)]
    pub(crate) write: PathBuf,
    /// Whole conversations, as tcp:INDEX or udp:INDEX. Repeat to select several.
    #[arg(long = "stream")]
    pub(crate) streams: Vec<String>,
    /// Include complete or incomplete IP datagrams containing this physical frame.
    #[arg(long = "datagram-frame")]
    pub(crate) datagram_frames: Vec<u64>,
    /// Match physical or reconstructed fields, including attached IP dependencies.
    #[arg(long)]
    pub(crate) filter: Option<String>,
    /// Maximum physical frames selected for export; at most 1,000,000.
    #[arg(long, default_value_t = 100_000)]
    pub(crate) max_selected_frames: usize,
    /// Compression of the saved capture file.
    #[arg(long, value_enum, default_value_t = Compression::None)]
    pub(crate) compression: Compression,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_millis(
            self.limits.max_duration_ms,
        ))
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
    let streams = args
        .streams
        .iter()
        .map(|value| super::offline_analysis::parse_stream_selector(value))
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
        args.compression.writer(std::io::BufWriter::with_capacity(
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
        ToolFormat::Text => write_plain_line(format_args!(
            "exported {} of {} physical frames to {}; {} complete and {} incomplete datagrams, {} unmatched stream selectors, {} unmatched datagram selectors",
            report.capture.frames_selected,
            report.capture.frames_read,
            report.path,
            report.selected_complete_datagrams,
            report.selected_incomplete_datagrams.len(),
            report.unmatched_streams.len(),
            report.unmatched_datagram_frames.len()
        )),
    }
}
