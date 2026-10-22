// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{path::PathBuf, sync::Arc, time::Duration};

use packetcraftr::os as library;
use packetcraftr_core::document::os_fingerprints;

use crate::{
    command_options::{Bounded, NumericPolicyArgs, RouteSelectionArgs, parse_target},
    errors::CliError,
    input::{InputKind, read_bounded_file},
    output::{self, contract::Format},
    rendering::write_stdout_line,
    system::{Runtime, prepare_workflow},
};

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Authorized numeric unicast IPv4/IPv6 target, including a link-local zone.
    pub(crate) target: String,
    /// TCP port expected to answer SYN with SYN/ACK.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) open_port: u16,
    /// Distinct TCP port expected to answer SYN with RST/ACK.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) closed_port: u16,
    /// Bounded operator-supplied fingerprint document.
    #[arg(long)]
    pub(crate) corpus: Option<PathBuf>,
    /// Attempts per authored probe (1..=3).
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=3))]
    pub(crate) attempts: u32,
    /// Response window per probe, in milliseconds (1..=1000).
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..=1000))]
    pub(crate) timeout_ms: u64,
    /// Maximum packets per second (1..=10).
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=10))]
    pub(crate) rate: u32,
    /// Operation deadline in milliseconds, including preparation (1..=30000).
    #[arg(long, default_value_t = 30000, value_parser = clap::value_parser!(u64).range(1..=30000))]
    pub(crate) max_duration_ms: u64,
    /// Total transmission ceiling, including cleanup and neighbor preparation.
    #[arg(long, default_value_t = library::MAX_PROBES)]
    pub(crate) max_probes: usize,
    /// Maximum retained/queued capture frames (at most 256).
    #[arg(long, default_value_t = library::MAX_EVIDENCE_FRAMES)]
    pub(crate) max_queue_frames: usize,
    /// Maximum retained/queued capture bytes (at most 1 MiB).
    #[arg(long, default_value_t = library::MAX_EVIDENCE_BYTES)]
    pub(crate) max_captured_bytes: usize,
    /// Maximum bytes from one captured frame (at most 4096).
    #[arg(long, default_value_t = library::MAX_FRAME_BYTES)]
    pub(crate) snap_length: usize,
    /// Maximum undecodable frames retained.
    #[arg(long, default_value_t = 256)]
    pub(crate) max_undecoded: usize,
    #[command(flatten)]
    pub(crate) route: RouteSelectionArgs,
    #[command(flatten)]
    pub(crate) policy: NumericPolicyArgs,
}

impl Bounded for Args {
    fn max_duration(&self) -> Duration {
        Duration::from_millis(self.max_duration_ms)
    }
}

impl crate::commands::Spec for Args {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;
    fn run_time(&self) -> Option<&dyn Bounded> {
        Some(self)
    }
    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            attempts: Count @ Operation, timeout_ms: Milliseconds @ Operation, rate: Count @ Operation,
            max_duration_ms: Milliseconds @ Operation, max_probes: Count @ Operation,
            max_queue_frames: Count @ NativeCapture, max_captured_bytes: Bytes @ NativeCapture,
            snap_length: Bytes @ NativeCapture, max_undecoded: Count @ ResultRetention,
        ]);
        self.policy.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        let format = invocation.format;
        let stream = &invocation.output;
        let corpus = match &self.corpus {
            Some(path) => Arc::new(
                os_fingerprints::parse(&read_bounded_file(
                    path,
                    os_fingerprints::MAX_DOCUMENT_BYTES,
                    InputKind::OsDocument,
                )?)
                .map_err(CliError::classified)?,
            ),
            None => library::builtin_corpus().map_err(CliError::classified)?,
        };
        let mut request = library::Request::new(
            parse_target(self.target.clone())?,
            self.open_port,
            self.closed_port,
            corpus,
        );
        request.attempts = self.attempts;
        request.timeout = Duration::from_millis(self.timeout_ms);
        request.probes_per_second = self.rate;
        request.limits = library::Limits {
            max_probes: self.max_probes,
            max_duration: self.max_duration(),
            evidence: packetcraftr::evidence::Limits {
                max_frames: self.max_queue_frames,
                max_bytes: self.max_captured_bytes,
                max_undecoded: self.max_undecoded,
            },
        };
        request.collection.capture = packetcraftr_netio::capture::Limits {
            max_frames: self.max_queue_frames,
            max_bytes: self.max_captured_bytes,
            snap_length: self.snap_length,
            overflow_policy: packetcraftr_netio::capture::OverflowPolicy::Fail,
        };
        request.collection.max_responses = self.max_queue_frames;
        request.collection.max_unmatched_frames = self.max_queue_frames;
        request.validate().map_err(CliError::classified)?;
        invocation.check()?;
        let workflow = prepare_workflow(
            &self.route,
            self.policy.into_policy(),
            request.timeout,
            request.collection.capture,
        )?;
        let mut client = workflow.client(invocation, Runtime::Workflow);
        if let Some(deadline) = invocation.deadline.clone() {
            client = client.with_deadline((*deadline).clone());
        }
        request.route = workflow.route;
        // Preserve explicit evidence ceilings; preparation supplies native decoding options.
        request.collection.decode = workflow.collection.decode;
        match format {
            Format::Ndjson => {
                let emit = crate::commands::execution::emitter(invocation, |event, stream| {
                    stream
                        .emit_published(
                            output::envelope::Published::<output::os::Event>::try_from(event)
                                .map_err(CliError::classified)?,
                        )
                        .map(|_| ())
                        .map_err(CliError::from)
                });
                let summary = client
                    .identify_os(request.clone(), emit)
                    .map_err(CliError::classified)?;
                invocation.check()?;
                stream
                    .complete_published(output::envelope::Published::<output::os::Event>::from(
                        summary,
                    ))
                    .map(|_| ())
                    .map_err(CliError::from)
            }
            _ => {
                let report = {
                    let collector = library::Collector::default();
                    let report = client
                        .identify_os(request.clone(), collector.clone())
                        .map_err(CliError::classified)?;
                    collector.finish(report).map_err(CliError::classified)?
                };
                invocation.check()?;
                if format == Format::Json {
                    crate::rendering::emit_published(
                        invocation,
                        output::contract::Command::IdentifyOs,
                        output::envelope::Published::<output::os::Report>::try_from(report)
                            .map_err(CliError::classified)?,
                    )
                } else {
                    render(invocation, report.report, stream.presentation())
                }
            }
        }?;
        Ok(crate::commands::CommandExit::SUCCESS)
    }
}

fn render(
    invocation: &crate::invocation::Invocation,
    report: library::Report,
    presentation: crate::invocation::Presentation,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "OS identification {}: {:?} — {}",
            report.target, report.identification.outcome, report.identification.reason
        ),
    )?;
    if presentation.verbose {
        for observation in &report.observations {
            write_stdout_line(invocation, format_args!("  observation: {observation:?}"))?;
        }
    }
    for candidate in report.identification.candidates {
        write_stdout_line(
            invocation,
            format_args!(
                "  {:?}: signature={} corpus={}@{} qualification=qualified",
                candidate.family, candidate.signature, candidate.corpus, candidate.corpus_version
            ),
        )?;
    }
    write_stdout_line(
        invocation,
        format_args!(
            "  observations={} transmissions={} bytes={} complete={}",
            report.observations.len(),
            report.stats.packets_attempted,
            report.stats.bytes,
            report.complete
        ),
    )
}
