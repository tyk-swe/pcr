// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use packetcraftr::Sink as _;
use packetcraftr::differential as lib;

use crate::command_options::{Bounded as _, MaxDurationArgs};
use crate::errors::CliError;
use crate::output;
use crate::output::contract::Format;
use crate::staged_output::StagedFile;

use super::parse_token;
use super::rendering;

pub(crate) const AFTER_LONG_HELP: &str = r"Run the cooperating Responder on the target side of a differential Campaign. It binds an ordinary UDP socket, records every token-bearing Canary it receives, and replies with a smaller deterministic echo naming the received payload digest. Datagrams without the campaign token are counted and ignored. The reception log is written no-clobber at clean stop (duration reached, idle after the first Canary, datagram bound, or cancellation) for a later differential-join.

Example:
  packetcraftr network differential-responder --port 40101 --token <32 hex chars> --log-file responder-log.jsonl";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// IPv4 address to bind.
    #[arg(long, default_value_t = Ipv4Addr::UNSPECIFIED)]
    pub(crate) bind: Ipv4Addr,
    /// UDP port to listen on.
    #[arg(long, default_value_t = 40101, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) port: u16,
    /// Campaign token as 32 hex characters, from the plan-only run.
    #[arg(long, value_name = "HEX")]
    pub(crate) token: String,
    /// Stop this many milliseconds after the first received Canary; omit to run until the duration bound.
    #[arg(long, default_value_t = 30_000)]
    pub(crate) idle_ms: u64,
    /// Maximum datagrams processed before stopping.
    #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) max_datagrams: u64,
    /// Write the reception log as JSON lines to this new file.
    #[arg(long)]
    pub(crate) log_file: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs,
}

impl crate::commands::Spec for Args {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.duration)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_datagrams: Count @ Operation,
            idle_ms: Milliseconds @ Operation,
        ]);
        self.duration.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

fn write_log(staged: &mut StagedFile, records: &[lib::ReceptionRecord]) -> Result<(), CliError> {
    for record in records {
        let line = serde_json::to_string(record).map_err(|source| {
            CliError::new(
                packetcraftr_core::error::Kind::Internal,
                format!("responder log record does not serialize: {source}"),
            )
        })?;
        staged
            .as_file_mut()
            .write_all(line.as_bytes())
            .and_then(|()| staged.as_file_mut().write_all(b"\n"))
            .map_err(|source| {
                CliError::new(
                    packetcraftr_core::error::Kind::Io,
                    format!("responder log write failed: {source}"),
                )
            })?;
    }
    Ok(())
}

fn run(invocation: &crate::invocation::Invocation, arguments: Args) -> Result<(), CliError> {
    let token = parse_token(&arguments.token)?;
    let mut staged = match &arguments.log_file {
        Some(path) => Some(StagedFile::stage(&invocation.terminal(), path)?),
        None => None,
    };
    let mut request = lib::ResponderRequest::new(arguments.bind, arguments.port, token);
    request.max_duration = arguments.duration.max_duration();
    request.idle_after_first =
        (arguments.idle_ms > 0).then(|| Duration::from_millis(arguments.idle_ms));
    request.max_datagrams = arguments.max_datagrams as usize;
    request.cancellation = Some(invocation.cancellation.clone());

    let format = invocation.format;
    let stream = &invocation.output;
    let collector = lib::ResponderCollector::default();

    let outcome = match format {
        Format::Ndjson => {
            let recording = collector.clone();
            let emit = crate::commands::execution::emitter(
                invocation,
                move |event: lib::ResponderEvent, stream| {
                    recording
                        .clone()
                        .publish(event.clone())
                        .map_err(CliError::classified)?;
                    rendering::emit_responder_event(event, stream)
                },
            );
            lib::respond(request, emit)
        }
        Format::Text | Format::Json => lib::respond(request, collector.clone()),
        other => other.unreachable(),
    };

    let report = match outcome {
        Ok(report) => report,
        Err(error) => {
            if let Some(staged) = &mut staged {
                let partial = collector.clone().finish(lib::ResponderReport::default());
                let _ = write_log(staged, &partial.records);
                let _ = staged.sync();
            }
            if let Some(staged) = staged {
                let _ = staged.persist();
            }
            return Err(CliError::classified(error));
        }
    };

    if format == Format::Ndjson {
        rendering::render_responder_complete(report.clone(), stream)?;
    }
    let aggregate = collector.finish(report);
    if let Some(staged) = &mut staged {
        write_log(staged, &aggregate.records)?;
        staged.sync()?;
    }
    if let Some(staged) = staged {
        staged.persist()?;
    }
    invocation.check()?;

    match format {
        Format::Ndjson => Ok(()),
        Format::Text => {
            let published =
                output::envelope::Published::<output::differential::ResponderReport>::from(
                    aggregate,
                );
            rendering::render_responder_text(invocation, &published.result)
        }
        Format::Json => crate::rendering::emit_published(
            invocation,
            output::contract::Command::DifferentialResponder,
            output::envelope::Published::<output::differential::ResponderReport>::from(aggregate),
        ),
        other => other.unreachable(),
    }
}
