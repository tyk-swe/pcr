// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod rules;
use crate::{
    command_options::{Compression, DecodeArgs, OfflineCaptureLimitsArgs},
    errors::CliError,
    filtering::FrameSelector,
    rendering::{StreamEncoder, emit_aggregate, write_plain_line},
};
use packetcraftr_cli::output::{
    self,
    contract::{Command, ToolFormat},
};
use packetcraftr_core::{
    analysis::pcap,
    budget::Deadline,
    error::{BoundaryError, Kind},
    transform::{self, HeaderRewrite, VlanRewrite},
};
use std::{net::IpAddr, path::PathBuf, time::Duration};
#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Source capture; - reads redirected stdin. gzip and Zstd are detected.
    pub(crate) path: PathBuf,
    /// New PCAPNG destination, published only when all frames are valid.
    #[arg(long)]
    pub(crate) write: PathBuf,
    /// Match original frame fields; unmatched frames are retained unchanged.
    #[arg(long)]
    pub(crate) filter: Option<String>,
    /// Ordered JSON rules under packetcraftr.rewrite/v1; at most 1 MiB and 64 rules.
    #[arg(long)]
    pub(crate) rules_file: Option<PathBuf>,
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
    let rules = if let Some(path) = &args.rules_file {
        if !patch.is_empty() || args.filter.is_some() {
            return Err(CliError::new(
                Kind::Cli,
                "--rules-file conflicts with direct edits and --filter",
            ));
        }
        rules::load(path)?
    } else {
        if patch.is_empty() {
            return Err(CliError::new(
                Kind::Cli,
                "rewrite requires a header edit or --rules-file",
            ));
        }
        patch.validate().map_err(CliError::classified)?;
        vec![rules::Rule {
            filter: args.filter,
            patch,
        }]
    };
    let registry = args.decode.registry()?;
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
            ))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let growth = rules
        .iter()
        .filter_map(|(_, patch)| patch.vlans.as_ref().map(|tags| tags.len() * 4))
        .max()
        .unwrap_or(0);
    let mut staged = crate::staged_output::StagedFile::stage(&args.write)?;
    let deadline = Deadline::new(Duration::from_millis(args.max_duration_ms))
        .with_cancellation(Some(crate::cancellation::signal().clone()));
    let mut reader = crate::input::open_capture(&args.path, args.limits.reader)?;
    let limits = pcap::Limits {
        max_frames: args.limits.max_frames,
        max_bytes: args.limits.max_bytes,
    };
    let mut writer = pcap::Writer::pcapng_with_options(
        args.compression.writer(staged.as_file_mut())?,
        pcap::PcapNgOptions {
            max_size: args.limits.reader.max_frame_bytes,
            max_interfaces: args.limits.reader.max_interfaces,
            stream_limits: limits,
            ..Default::default()
        },
    )
    .map_err(CliError::classified)?;
    let mut counts = vec![0u64; rules.len()];
    let report = pcap::map_frames(&mut reader, &mut writer, limits, growth, |number, frame| {
        check_deadline(&deadline)?;
        let mut changed = frame.clone();
        for (index, (filter, patch)) in rules.iter().enumerate() {
            if filter
                .as_ref()
                .map(|filter| filter.keep(number, frame))
                .transpose()
                .map_err(CliError::into_boundary_error)?
                .unwrap_or(true)
            {
                changed = transform::rewrite(
                    &changed,
                    patch,
                    transform::RewriteLimits {
                        max_output_bytes: args.limits.reader.max_frame_bytes,
                    },
                )
                .map_err(BoundaryError::from_error)?;
                counts[index] += 1;
            }
        }
        check_deadline(&deadline)?;
        Ok(changed)
    })
    .map_err(CliError::classified)?;
    let _ = writer.into_inner().finish().map_err(CliError::classified)?;
    staged.sync()?;
    check_deadline(&deadline).map_err(CliError::classified)?;
    staged.persist()?;
    let report = output::rewrite::Report {
        path: args.write.display().to_string(),
        rule_matches: counts,
        capture: report,
    };
    match format {
        ToolFormat::Json => emit_aggregate(Command::Rewrite, report, Vec::new()),
        ToolFormat::Ndjson => stream.complete(report, Vec::new()).map_err(Into::into),
        ToolFormat::Text => write_plain_line(format_args!(
            "rewrote {} of {} frames across {} interfaces into {}",
            report.capture.frames_changed,
            report.capture.frames_read,
            report.capture.interfaces,
            report.path
        )),
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
