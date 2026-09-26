// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;
mod rules;

use self::arguments::Args;
use crate::output::{
    self,
    contract::{Command, ToolFormat},
    rewrite::MAX_REPORTED_CHANGES,
};
use crate::{
    commands::offline_analysis::Retained,
    errors::CliError,
    filtering::FrameSelector,
    rendering::{StreamEncoder, emit_aggregate},
};
use packetcraftr_core::{
    budget::Deadline,
    capture_file,
    decode::Dissector,
    error::{BoundaryError, Kind},
    transform::{self, ChecksumMode, FieldEdits, HeaderRewrite},
};

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(self.duration.max_duration())
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
        rules::load(path, &registry, checksum_mode)?
    } else {
        if patch.is_empty() && args.sets.is_empty() {
            return Err(CliError::new(
                Kind::Usage,
                "rewrite requires a header edit, --set, or --rules-file",
            ));
        }
        patch.validate().map_err(CliError::classified)?;
        let edits = if args.sets.is_empty() {
            None
        } else {
            Some(
                FieldEdits::compile(&args.sets, checksum_mode, &registry)
                    .map_err(|error| CliError::caused(Kind::Usage, &error))?,
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
            Kind::Usage,
            "--checksum-mode requires field assignments via --set or a v2 rules file",
        ));
    }
    if args.dry_run && rules.iter().any(|rule| !rule.patch.is_empty()) {
        return Err(CliError::new(
            Kind::Usage,
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
