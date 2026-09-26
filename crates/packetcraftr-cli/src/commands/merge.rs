// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    command_options::{Compression, OfflineCaptureLimitsArgs},
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate, write_plain_line},
};
use packetcraftr_cli::output::{self, contract::ToolFormat};
use packetcraftr_core::{capture_file, error::Kind};
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Captures in stable tie-breaking order; at most one may read stdin with -.
    #[arg(required = true, num_args = 2..)]
    pub(crate) paths: Vec<PathBuf>,
    /// New PCAPNG destination. Existing files are never overwritten.
    #[arg(long)]
    pub(crate) write: PathBuf,
    /// Compression of the saved PCAPNG file.
    #[arg(long, value_enum, default_value_t = Compression::None)]
    pub(crate) compression: Compression,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
}

pub(crate) fn run(args: Args, format: ToolFormat, stream: &StreamEncoder) -> Result<(), CliError> {
    crate::input::validate_capture_stream_limits(args.limits)?;
    if args.paths.len() > 64 || args.paths.iter().filter(|p| *p == Path::new("-")).count() > 1 {
        return Err(CliError::new(
            Kind::Usage,
            "merge accepts at most 64 captures and one stdin source",
        ));
    }
    let mut staged = crate::staged_output::StagedFile::stage(&args.write)?;
    let mut sources = args
        .paths
        .iter()
        .map(|path| {
            Ok(capture_file::MergeSource {
                name: path.display().to_string(),
                reader: crate::input::open_capture(path, args.limits.reader)?,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let mut writer = capture_file::Writer::pcapng_with_options(
        args.compression.writer(std::io::BufWriter::with_capacity(
            64 * 1024,
            staged.as_file_mut(),
        ))?,
        capture_file::PcapNgOptions {
            max_size: args.limits.reader.max_frame_bytes,
            // --max-interfaces bounds each input section, not the one output section.
            max_interfaces: capture_file::DEFAULT_TOTAL_INTERFACE_LIMIT,
            stream_limits: capture_file::Limits {
                max_frames: args.limits.max_frames,
                max_bytes: args.limits.max_bytes,
            },
            ..Default::default()
        },
    )
    .map_err(CliError::classified)?;
    let report = capture_file::merge(
        &mut sources,
        &mut writer,
        capture_file::MergeLimits {
            streams: capture_file::Limits {
                max_frames: args.limits.max_frames,
                max_bytes: args.limits.max_bytes,
            },
            ..Default::default()
        },
    )
    .map_err(CliError::classified)?;
    let _ = writer.into_inner().finish().map_err(CliError::classified)?;
    staged.sync()?;
    crate::cancellation::check()?;
    staged.persist()?;
    let report = output::merge::Report::new(args.write.display().to_string(), report);
    match format {
        ToolFormat::Json => emit_aggregate(output::contract::Command::Merge, report, Vec::new()),
        ToolFormat::Ndjson => stream.complete(report, Vec::new()).map_err(Into::into),
        ToolFormat::Text => write_plain_line(format_args!(
            "merged {} frames ({} bytes) across {} interfaces into {}",
            report.frames,
            report.captured_bytes,
            report.interfaces.len(),
            report.path
        )),
    }
}
