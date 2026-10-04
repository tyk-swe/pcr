// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use self::arguments::Args;
use crate::output::{
    self,
    contract::{Command, Format},
    rewrite::MAX_REPORTED_CHANGES,
};
use crate::{
    errors::CliError,
    filtering,
    rendering::{Retained, StreamEncoder, emit_aggregate},
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

impl super::Spec for Args {
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
        format: Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(crate) fn run(args: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
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
        Format::Json => emit_aggregate(Command::Rewrite, report, Vec::new()),
        Format::Ndjson => stream.complete(report, Vec::new()).map_err(Into::into),
        Format::Text => rendering::render_text(&report),
        other => other.unreachable(),
    }
}

fn check_deadline(deadline: &Deadline) -> Result<(), BoundaryError> {
    deadline.enforce().map_err(BoundaryError::from_error)
}

#[cfg(test)]
mod tests {

    use clap::Parser;

    use super::*;

    #[test]
    fn the_address_table_accepts_4096_arguments_and_refuses_one_more() {
        // The argument vector is exercised in-process: a command line long
        // enough to hold this many entries cannot spawn on every platform.
        let entries = |count: usize| {
            (0..count)
                .flat_map(|index| {
                    let [_, _, high, low] = u32::try_from(index).unwrap().to_be_bytes();
                    [
                        "--map-ip".to_owned(),
                        format!("10.{high}.{low}.1=172.16.{high}.{low}"),
                    ]
                })
                .collect::<Vec<_>>()
        };
        let rewrite = |entries: &[String]| {
            let mut argv = vec![
                "packetcraftr".to_owned(),
                "rewrite".to_owned(),
                "in.pcapng".to_owned(),
                "--write".to_owned(),
                "out.pcapng".to_owned(),
            ];
            argv.extend(entries.iter().cloned());
            let cli = crate::cli::Cli::try_parse_from(argv).expect("arguments parse");
            let crate::commands::CommandLine::Rewrite(args) = cli.command else {
                panic!("rewrite arguments");
            };
            args
        };
        let full = rewrite(&entries(transform::MAX_ADDRESS_MAP_ENTRIES));
        assert_eq!(full.map_ips.len(), transform::MAX_ADDRESS_MAP_ENTRIES);
        AddressMap::new(&full.map_ips, &full.map_macs).expect("the table holds 4096");
        let over = rewrite(&entries(transform::MAX_ADDRESS_MAP_ENTRIES + 1));
        let (stream, _) = crate::test_support::stream(Command::Rewrite);
        let error = run(over, Format::Text, &stream).expect_err("one more is refused");
        assert_eq!(error.exit_code(), 2);
        assert!(error.to_string().contains("address map entries=4096"));
    }
}
