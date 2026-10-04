// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use self::arguments::{Args, OrderArg};
use crate::output::{self, contract::Format};
use crate::{
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate},
};
use packetcraftr_core::{capture_file, error::Kind};
use std::path::Path;

impl super::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
    ];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.limits.resources(settings);
        crate::resources::declare!(settings, self, [
            max_reorder_frames: Count @ Operation if self.max_reorder_frames > 0,
        ]);
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
    args.limits.validate()?;
    let reorder = args.max_reorder_frames > 0;
    if reorder && args.order == OrderArg::Append {
        return Err(CliError::new(
            Kind::Usage,
            "--order append keeps timestamps verbatim and cannot be combined with --max-reorder-frames",
        ));
    }
    if args.paths.len() < 2 && !reorder {
        return Err(CliError::new(
            Kind::Usage,
            "merge needs at least two captures unless --max-reorder-frames is set",
        ));
    }
    if args.paths.len() > capture_file::MAX_MERGE_SOURCES
        || args.paths.iter().filter(|p| *p == Path::new("-")).count() > 1
    {
        return Err(CliError::new(
            Kind::Usage,
            format!(
                "merge accepts at most {} captures and one stdin source",
                capture_file::MAX_MERGE_SOURCES
            ),
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
        args.compression
            .for_file()
            .writer(std::io::BufWriter::with_capacity(
                64 * 1024,
                staged.as_file_mut(),
            ))?,
        capture_file::PcapNgOptions {
            max_size: args.limits.reader.max_frame_bytes,
            // --max-interfaces bounds each input section, not the one output section.
            max_interfaces: capture_file::DEFAULT_MAX_TOTAL_INTERFACES,
            stream_limits: args.limits.stream_limits(),
            ..Default::default()
        },
    )
    .map_err(CliError::classified)?;
    let report = capture_file::merge(
        &mut sources,
        &mut writer,
        capture_file::MergeLimits {
            streams: args.limits.stream_limits(),
            order: args.order.into(),
            max_reorder_frames: usize::try_from(args.max_reorder_frames).unwrap_or(usize::MAX),
            ..Default::default()
        },
    )
    .map_err(CliError::classified)?;
    let _ = writer.into_inner().finish().map_err(CliError::classified)?;
    staged.sync()?;
    crate::cancellation::check()?;
    staged.persist()?;
    let report = output::merge::Report::from((args.write.display().to_string(), report));
    match format {
        Format::Json => emit_aggregate(output::contract::Command::Merge, report, Vec::new()),
        Format::Ndjson => stream.complete(report, Vec::new()).map_err(Into::into),
        Format::Text => rendering::render_text(&report),
        other => other.unreachable(),
    }
}
