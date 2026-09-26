// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `rewrite`: rewrites capture headers and fields with checked lengths and
//! transport checksums into a new PCAPNG file.

pub(super) mod arguments;
mod rendering;

use self::arguments::Args;
use crate::output::{
    self,
    contract::{Command, ToolFormat},
    rewrite::MAX_REPORTED_CHANGES,
};
use crate::{
    commands::offline_analysis::Retained,
    errors::CliError,
    filtering,
    rendering::{StreamEncoder, emit_aggregate},
};
use packetcraftr_core::{
    budget::Deadline,
    capture_file,
    decode::Dissector,
    error::{BoundaryError, Kind},
    transform::{
        self, ChecksumMode, HeaderRewrite,
        rules::{self, Rules},
    },
};

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.duration)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.duration.resources(settings);
        self.limits.resources(settings);
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
    crate::input::validate_capture_stream_limits(args.limits)?;
    let checksum_mode = args
        .checksum_mode
        .map(ChecksumMode::from)
        .unwrap_or_default();
    let patch = HeaderRewrite {
        source_mac: args.source_mac,
        destination_mac: args.destination_mac,
        source_ip: args.source_ip,
        destination_ip: args.destination_ip,
        source_port: args.source_port,
        destination_port: args.destination_port,
        vlans: if args.strip_vlans {
            Some(Vec::new())
        } else if !args.vlans.is_empty() {
            Some(args.vlans)
        } else {
            None
        },
    };
    let registry = args.decode.registry()?;
    let rules = if let Some(path) = &args.rules_file {
        if !patch.is_empty() || args.filter.is_some() || !args.sets.is_empty() {
            return Err(CliError::new(
                Kind::Usage,
                "--rules-file conflicts with direct edits, --set, and --filter",
            ));
        }
        let document =
            crate::input::read_bounded_json_document(path, rules::MAX_REWRITE_DOCUMENT_BYTES)?;
        Rules::parse(&document, checksum_mode, &registry).map_err(CliError::classified)?
    } else {
        if patch.is_empty() && args.sets.is_empty() {
            return Err(CliError::new(
                Kind::Usage,
                "rewrite requires a header edit, --set, or --rules-file",
            ));
        }
        Rules::single(
            args.filter.clone(),
            patch,
            &args.sets,
            checksum_mode,
            &registry,
        )
        .map_err(CliError::classified)?
    };
    if args.checksum_mode.is_some() && !rules.has_field_edits() {
        return Err(CliError::new(
            Kind::Usage,
            "--checksum-mode requires field assignments via --set or a v2 rules file",
        ));
    }
    if args.dry_run && rules.has_header_edits() {
        return Err(CliError::new(
            Kind::Usage,
            "--dry-run reports field-assignment changes only; it cannot preview header rewrites",
        ));
    }
    let rules = rules.try_map_filters(|filter| {
        filtering::frame_selector(&filter, &registry, args.limits.reader.max_frame_bytes)
    })?;
    let growth = rules.maximum_growth();
    let mut staged = if args.dry_run {
        None
    } else {
        Some(crate::staged_output::StagedFile::stage(&args.write)?)
    };
    let deadline = Deadline::new(args.duration.max_duration())
        .with_cancellation(Some(crate::cancellation::signal().clone()));
    let mut reader = crate::input::open_capture(&args.path, args.limits.reader)?;
    let limits = capture_file::Limits {
        max_frames: args.limits.max_frames,
        max_bytes: args.limits.max_bytes,
    };
    let inner: Box<dyn std::io::Write> = match staged.as_mut() {
        Some(staged) => Box::new(std::io::BufWriter::with_capacity(
            64 * 1024,
            staged.as_file_mut(),
        )),
        None => Box::new(std::io::sink()),
    };
    let mut writer = capture_file::Writer::pcapng_with_options(
        args.compression.for_file().writer(inner)?,
        capture_file::PcapNgOptions {
            max_size: args.limits.reader.max_frame_bytes,
            // --max-interfaces bounds each input section, not the one output section.
            max_interfaces: capture_file::DEFAULT_TOTAL_INTERFACE_LIMIT,
            stream_limits: limits,
            ..Default::default()
        },
    )
    .map_err(CliError::classified)?;
    let dissector = Dissector::new(registry.clone());
    let mut counts = vec![0u64; rules.len()];
    let mut changes = Retained::new(MAX_REPORTED_CHANGES);
    let report =
        capture_file::map_frames(&mut reader, &mut writer, limits, growth, |number, frame| {
            check_deadline(&deadline)?;
            let changed = rules.apply(
                frame,
                &dissector,
                transform::RewriteLimits {
                    max_output_bytes: args.limits.reader.max_frame_bytes,
                },
                |filter| {
                    filter.keep(number, frame).map_err(|error| {
                        filtering::frame_error(number, error).into_boundary_error()
                    })
                },
                |index, applied| {
                    for change in applied {
                        changes
                            .push(|| output::rewrite::Change::from((number, index as u64, change)));
                    }
                    counts[index] += 1;
                },
            )?;
            check_deadline(&deadline)?;
            Ok(changed)
        })
        .map_err(CliError::classified)?;
    let _ = writer.into_inner().finish().map_err(CliError::classified)?;
    if let Some(staged) = staged {
        staged.sync()?;
        check_deadline(&deadline).map_err(CliError::classified)?;
        staged.persist()?;
    }
    let changes_omitted = changes.omitted();
    let report = output::rewrite::Report::from((
        args.write.display().to_string(),
        counts,
        report,
        args.dry_run,
        changes.into_items(),
        changes_omitted,
    ));
    match format {
        ToolFormat::Json => emit_aggregate(Command::Rewrite, report, Vec::new()),
        ToolFormat::Ndjson => stream.complete(report, Vec::new()).map_err(Into::into),
        ToolFormat::Text => rendering::render_text(&report),
    }
}

fn check_deadline(deadline: &Deadline) -> Result<(), BoundaryError> {
    deadline.enforce().map_err(|error| match error {
        packetcraftr_core::budget::Interrupted::Cancelled(error) => {
            BoundaryError::from_error(error)
        }
        packetcraftr_core::budget::Interrupted::Exceeded(error) => BoundaryError::with_source(
            error.to_string(),
            packetcraftr_core::error::Classification::new(
                "policy.rewrite_duration",
                Kind::Policy,
                None,
            ),
            Vec::new(),
            error,
        ),
        _ => BoundaryError::from_error(packetcraftr_core::budget::Cancelled),
    })
}
