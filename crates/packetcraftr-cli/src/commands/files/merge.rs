// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
pub(in crate::commands) mod output;

use self::arguments::{Args, OrderArg};
use crate::{errors::CliError, rendering::write_summary_line};
use packetcraftr_core::{capture_file, error::Kind};
use std::path::Path;

impl crate::commands::Spec for Args {
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
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(crate) fn run(invocation: &crate::invocation::Invocation, args: Args) -> Result<(), CliError> {
    let limits = args.limits.limits()?;
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
    let mut staged = crate::staged_output::StagedFile::stage(invocation, &args.write)?;
    let mut sources = args
        .paths
        .iter()
        .map(|path| {
            Ok(capture_file::MergeSource {
                name: path.display().to_string(),
                reader: crate::input::open_capture(invocation, path, limits)?,
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
            max_size: limits.reader_bounds().max_frame_bytes,
            // --max-interfaces bounds each input section, not the one output section.
            max_interfaces: capture_file::DEFAULT_MAX_TOTAL_INTERFACES,
            stream_limits: limits.stream_limits(),
            ..Default::default()
        },
    )
    .map_err(CliError::classified)?;
    let report = capture_file::merge(
        &mut sources,
        &mut writer,
        capture_file::MergeLimits {
            streams: limits.stream_limits(),
            order: args.order.into(),
            max_reorder_frames: usize::try_from(args.max_reorder_frames).unwrap_or(usize::MAX),
            ..Default::default()
        },
    )
    .map_err(CliError::classified)?;
    let _ = writer.into_inner().finish().map_err(CliError::classified)?;
    staged.sync()?;
    staged.persist()?;
    let report = output::Report::from((args.write.display().to_string(), report));
    crate::commands::offline_analysis::complete_application(
        invocation,
        crate::output::contract::Command::Merge,
        report,
        |report| report,
        |invocation, report| {
            invocation
                .output
                .presentation()
                .details(invocation, "Capture sources", report)?;
            write_summary_line(
                invocation,
                format_args!(
                    "merged {} frames ({} bytes) across {} interfaces into {}",
                    report.frames,
                    report.captured_bytes,
                    report.interfaces.len(),
                    report.path
                ),
            )
        },
    )
}
