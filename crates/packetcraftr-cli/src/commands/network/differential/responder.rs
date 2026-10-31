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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invocation::{Invocation, StreamEncoder};
    use crate::output::contract::Command;
    use clap::Parser as _;
    use lib::canary;
    use std::net::UdpSocket;
    use std::thread;

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn cancelled_responder_still_publishes_its_reception_log() {
        let directory = std::env::temp_dir().join(format!(
            "packetcraftr-responder-cancel-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).expect("test directory");
        let log = directory.join("responder-log.jsonl");
        for attempt in 0..3 {
            let _ = std::fs::remove_file(&log);
            if try_cancelled_run(&log, attempt) {
                let _ = std::fs::remove_dir_all(&directory);
                return;
            }
        }
        panic!("responder never answered across retries");
    }

    fn try_cancelled_run(log: &std::path::Path, _attempt: usize) -> bool {
        let port = {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
            socket.local_addr().expect("address").port()
        };
        let token_hex = "42".repeat(16);
        let wrap = Wrap::try_parse_from([
            "test",
            "--bind",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--token",
            &token_hex,
            "--idle-ms",
            "0",
            "--max-duration-ms",
            "30000",
            "--log-file",
            log.to_str().expect("log path is UTF-8"),
        ])
        .expect("arguments parse");
        let invocation = Invocation::new(
            Format::Text,
            StreamEncoder::new(Command::DifferentialResponder, Vec::<u8>::new()),
            None,
            Default::default(),
            None,
        );
        let cancellation = invocation.cancellation.clone();
        let handle = thread::spawn(move || run(&invocation, wrap.args));

        let probe_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("probe socket");
        probe_socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        let token = [0x42; 16];
        let payload = canary::build_probe(&token, 1, 7, 256);
        let target = (Ipv4Addr::LOCALHOST, port);
        let mut buffer = [0_u8; 128];
        let mut answered = false;
        let probe_deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < probe_deadline {
            if handle.is_finished() {
                break;
            }
            probe_socket.send_to(&payload, target).expect("probe sends");
            match probe_socket.recv_from(&mut buffer) {
                Ok(_) => {
                    answered = true;
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
        if !answered {
            cancellation.cancel();
            let _ = handle.join();
            return false;
        }
        thread::sleep(Duration::from_millis(300));
        cancellation.cancel();
        let outcome = handle.join().expect("responder thread finishes");
        assert!(outcome.is_err(), "cancellation reports as an error");

        let contents = std::fs::read_to_string(log).expect("reception log was published");
        let expected = lib::hex(&canary::payload_sha256(&payload));
        let found = contents
            .lines()
            .filter_map(|line| serde_json::from_str::<lib::ReceptionRecord>(line).ok())
            .any(|record| record.attempt_seq == 7 && record.payload_sha256 == expected);
        assert!(found, "log holds the reception record: {contents}");
        true
    }
}
