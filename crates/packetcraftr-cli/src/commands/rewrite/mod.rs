// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod rules;
use crate::{
    command_options::{Compression, DecodeArgs, OfflineCaptureLimitsArgs},
    commands::offline_analysis::Retained,
    errors::CliError,
    filtering::FrameSelector,
    rendering::{StreamEncoder, emit_aggregate, write_plain_line},
};
use packetcraftr_cli::output::{
    self,
    contract::{Command, ToolFormat},
    rewrite::MAX_REPORTED_CHANGES,
};
use packetcraftr_core::{
    analysis::pcap,
    budget::Deadline,
    decode::Dissector,
    error::{BoundaryError, Kind},
    transform::{self, ChecksumMode, FieldAssignment, FieldEdits, HeaderRewrite, VlanRewrite},
};
use std::{net::IpAddr, path::PathBuf, time::Duration};
#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Source capture; - reads redirected stdin. gzip and Zstd are detected.
    pub(crate) path: PathBuf,
    /// New PCAPNG destination, published only when all frames are valid.
    /// With --dry-run the destination is only named, never created.
    #[arg(long)]
    pub(crate) write: PathBuf,
    /// Match original frame fields; unmatched frames are retained unchanged.
    #[arg(long)]
    pub(crate) filter: Option<String>,
    /// Ordered JSON rules under packetcraftr.rewrite/v1 (header patches) or
    /// /v2 (field assignments); at most 1 MiB and 64 rules.
    #[arg(long)]
    pub(crate) rules_file: Option<PathBuf>,
    /// Assign one fixed-width field in place, <protocol>[#occurrence].<field>=
    /// <value>; repeatable. Supports ipv4.ttl, ipv6.hop_limit, tcp.sequence,
    /// tcp.acknowledgment, tcp/udp ports, and dns.id. Header edits apply first
    /// when combined with them; conflicts with --rules-file.
    #[arg(long = "set", value_name = "FIELD=VALUE", value_parser = rules::assignment)]
    pub(crate) sets: Vec<FieldAssignment>,
    /// Checksum behavior for field assignments: repair recomputes covering
    /// checksums; preserve keeps checksum bytes exactly.
    #[arg(long, value_enum)]
    pub(crate) checksum_mode: Option<rules::ChecksumArg>,
    /// Report the field-edit changes --set or v2 rules would make, without
    /// creating or replacing the destination. Requires assignments only.
    #[arg(long)]
    pub(crate) dry_run: bool,
    #[arg(long,value_parser=rules::mac)]
    pub(crate) source_mac: Option<[u8; 6]>,
    #[arg(long,value_parser=rules::mac)]
    pub(crate) destination_mac: Option<[u8; 6]>,
    #[arg(long)]
    pub(crate) source_ip: Option<IpAddr>,
    #[arg(long)]
    pub(crate) destination_ip: Option<IpAddr>,
    #[arg(long)]
    pub(crate) source_port: Option<u16>,
    #[arg(long)]
    pub(crate) destination_port: Option<u16>,
    /// Replace the outer VLAN stack; repeat VID or TPID:VID[:PRIORITY[:DEI]].
    #[arg(long="vlan",value_parser=rules::vlan,conflicts_with="strip_vlans")]
    pub(crate) vlans: Vec<VlanRewrite>,
    #[arg(long)]
    pub(crate) strip_vlans: bool,
    #[arg(long,value_enum,default_value_t=Compression::None)]
    pub(crate) compression: Compression,
    #[arg(long,default_value_t=3_600_000,value_parser=clap::value_parser!(u64).range(1..=3_600_000))]
    pub(crate) max_duration_ms: u64,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
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
                Kind::Cli,
                "--rules-file conflicts with direct edits, --set, and --filter",
            ));
        }
        rules::load(path, &registry, checksum_mode)?
    } else {
        if patch.is_empty() && args.sets.is_empty() {
            return Err(CliError::new(
                Kind::Cli,
                "rewrite requires a header edit, --set, or --rules-file",
            ));
        }
        patch.validate().map_err(CliError::classified)?;
        let edits = if args.sets.is_empty() {
            None
        } else {
            Some(
                FieldEdits::compile(&args.sets, checksum_mode, &registry)
                    .map_err(|error| CliError::caused(Kind::Cli, &error))?,
            )
        };
        vec![rules::Rule {
            filter: args.filter.clone(),
            patch,
            edits,
        }]
    };
    if args.checksum_mode.is_some() && rules.iter().all(|rule| !rule.has_edits()) {
        return Err(CliError::new(
            Kind::Cli,
            "--checksum-mode requires field assignments via --set or a v2 rules file",
        ));
    }
    if args.dry_run && rules.iter().any(|rule| !rule.patch.is_empty()) {
        return Err(CliError::new(
            Kind::Cli,
            "--dry-run reports field-assignment changes only; it cannot preview header rewrites",
        ));
    }
    let rules = rules
        .into_iter()
        .map(|rule| {
            Ok((
                FrameSelector::compile_optional(
                    rule.filter.as_deref(),
                    &registry,
                    args.limits.reader.max_frame_bytes,
                )?,
                rule.patch,
                rule.edits,
            ))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let growth = rules
        .iter()
        .filter_map(|(_, patch, _)| patch.vlans.as_ref().map(|tags| tags.len() * 4))
        .max()
        .unwrap_or(0);
    let mut staged = if args.dry_run {
        None
    } else {
        Some(crate::staged_output::StagedFile::stage(&args.write)?)
    };
    let deadline = Deadline::new(Duration::from_millis(args.max_duration_ms))
        .with_cancellation(Some(crate::cancellation::signal().clone()));
    let mut reader = crate::input::open_capture(&args.path, args.limits.reader)?;
    let limits = pcap::Limits {
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
    let mut writer = pcap::Writer::pcapng_with_options(
        args.compression.writer(inner)?,
        pcap::PcapNgOptions {
            max_size: args.limits.reader.max_frame_bytes,
            max_interfaces: args.limits.reader.max_interfaces,
            stream_limits: limits,
            ..Default::default()
        },
    )
    .map_err(CliError::classified)?;
    let dissector = Dissector::new(registry.clone());
    let mut counts = vec![0u64; rules.len()];
    let mut changes = Retained::new(MAX_REPORTED_CHANGES);
    let report = pcap::map_frames(&mut reader, &mut writer, limits, growth, |number, frame| {
        check_deadline(&deadline)?;
        let mut changed = frame.clone();
        for (index, (filter, patch, edits)) in rules.iter().enumerate() {
            if filter
                .as_ref()
                .map(|filter| filter.keep(number, frame))
                .transpose()
                .map_err(CliError::into_boundary_error)?
                .unwrap_or(true)
            {
                if !patch.is_empty() {
                    changed = transform::rewrite(
                        &changed,
                        patch,
                        transform::RewriteLimits {
                            max_output_bytes: args.limits.reader.max_frame_bytes,
                        },
                    )
                    .map_err(BoundaryError::from_error)?;
                }
                if let Some(edits) = edits {
                    let outcome = edits
                        .apply(
                            &changed,
                            &dissector,
                            transform::RewriteLimits {
                                max_output_bytes: args.limits.reader.max_frame_bytes,
                            },
                        )
                        .map_err(BoundaryError::from_error)?;
                    for change in outcome.changes {
                        changes.push(|| output::rewrite::Change {
                            frame: number,
                            rule: index as u64,
                            change,
                        });
                    }
                    changed = outcome.frame;
                }
                counts[index] += 1;
            }
        }
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
    let report = output::rewrite::Report {
        path: args.write.display().to_string(),
        rule_matches: counts,
        capture: report,
        dry_run: args.dry_run,
        changes: changes.into_items(),
        changes_omitted,
    };
    match format {
        ToolFormat::Json => emit_aggregate(Command::Rewrite, report, Vec::new()),
        ToolFormat::Ndjson => stream.complete(report, Vec::new()).map_err(Into::into),
        ToolFormat::Text => {
            if args.dry_run {
                write_plain_line(format_args!(
                    "dry-run: {} of {} frames would change across {} interfaces; \
                     {} changes reported, {} omitted",
                    report.capture.frames_changed,
                    report.capture.frames_read,
                    report.capture.interfaces,
                    report.changes.len(),
                    report.changes_omitted
                ))
            } else {
                write_plain_line(format_args!(
                    "rewrote {} of {} frames across {} interfaces into {}",
                    report.capture.frames_changed,
                    report.capture.frames_read,
                    report.capture.interfaces,
                    report.path
                ))
            }
        }
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
