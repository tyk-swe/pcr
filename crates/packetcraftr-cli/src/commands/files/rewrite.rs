// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;

use self::arguments::Args;
use crate::output::{
    self,
    contract::{Command, Format},
    rewrite::MAX_REPORTED_CHANGES,
};
use crate::{
    errors::CliError,
    filtering,
    rendering::{Retained, StreamEncoder, emit_aggregate, write_summary_line},
};
use packetcraftr_core::{
    budget::Deadline,
    capture_file,
    decode::Dissector,
    error::{BoundaryError, Kind},
    transform::{
        self, AddressMap, ChecksumMode, HeaderRewrite,
        rules::{self, Rules},
    },
};

impl crate::commands::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
    ];
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
    args.limits.validate()?;
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
    let map = if args.map_ips.is_empty() && args.map_macs.is_empty() {
        None
    } else {
        Some(
            AddressMap::new(&args.map_ips, &args.map_macs)
                .map_err(|error| CliError::caused(Kind::Usage, &error))?,
        )
    };
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
        if patch.is_empty() && args.sets.is_empty() && map.is_none() {
            return Err(CliError::new(
                Kind::Usage,
                "rewrite requires a header edit, --map-ip, --map-mac, --set, or --rules-file",
            ));
        }
        let rules = Rules::single(
            args.filter.clone(),
            patch,
            &args.sets,
            checksum_mode,
            &registry,
        )
        .map_err(CliError::classified)?;
        match map {
            Some(map) => rules.with_address_map(map),
            None => rules,
        }
    };
    if args.checksum_mode.is_some() && !rules.has_field_edits() {
        return Err(CliError::new(
            Kind::Usage,
            "--checksum-mode requires field assignments via --set or a v1 rules file",
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
        Some(crate::staged_output::StagedFile::stage(
            invocation,
            &args.write,
        )?)
    };
    let deadline = Deadline::new(args.duration.max_duration())
        .with_cancellation(Some(invocation.cancellation.clone()));
    let mut reader = crate::input::open_capture(invocation, &args.path, args.limits.reader)?;
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
            max_interfaces: capture_file::DEFAULT_MAX_TOTAL_INTERFACES,
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
        Format::Json => emit_aggregate(invocation, Command::Rewrite, report, Vec::new()),
        Format::Ndjson => stream.complete(report, Vec::new()).map_err(Into::into),
        Format::Text => {
            stream
                .presentation()
                .details(invocation, "Rewrite evidence", &report)?;
            render_text(invocation, &report)
        }
        other => other.unreachable(),
    }
}

fn render_text(
    invocation: &crate::invocation::Invocation,
    report: &output::rewrite::Report,
) -> Result<(), CliError> {
    for change in &report.changes {
        crate::rendering::write_stdout_line(
            invocation,
            format_args!(
                "frame={} layer={} field={} {} -> {} origin={}",
                change.frame,
                change.layer,
                change.field,
                change.old,
                change.new,
                change.origin.as_str()
            ),
        )?;
    }
    if report.dry_run {
        write_summary_line(
            invocation,
            format_args!(
                "dry-run: {} of {} frames would change across {} interfaces; \
             {} changes reported, {} omitted",
                report.capture.frames_changed,
                report.capture.frames_read,
                report.capture.interfaces,
                report.changes.len(),
                report.changes_omitted
            ),
        )
    } else {
        write_summary_line(
            invocation,
            format_args!(
                "rewrote {} of {} frames across {} interfaces into {}",
                report.capture.frames_changed,
                report.capture.frames_read,
                report.capture.interfaces,
                report.path
            ),
        )
    }
}

fn check_deadline(deadline: &Deadline) -> Result<(), BoundaryError> {
    deadline.enforce().map_err(BoundaryError::from_error)
}
