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

When the duration is reached, the Responder publishes its report and exits successfully. Output failures still return an error.

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

use crate::output::contract::PublishedType;

impl crate::commands::Spec for Args {
    const PUBLISHED: &'static [PublishedType] = &[
        PublishedType {
            definition: "differentialResponderSuccess",
            command: "differential-responder",
            rust_types: &["crate::commands::network::differential::output::ResponderReport"],
            events: &[],
            example: "examples/documents/output-differential-responder-success.json",
        },
        PublishedType {
            definition: "differentialResponderStreamSuccess",
            command: "differential-responder",
            rust_types: &["crate::commands::network::differential::output::ResponderEvent"],
            events: &["complete", "received"],
            example: "examples/documents/output-differential-responder-complete.json",
        },
    ];
    const FORMATS: &'static [Format] = crate::output::contract::TEXT_JSON_NDJSON;
    const CANCELLATION: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.duration)
    }

    fn publication_duration(&self) -> Option<Duration> {
        Some(
            self.duration.max_duration()
                + Duration::from_millis(crate::resources::OUTPUT_TIMEOUT_MS),
        )
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
    request.cancellation = Some(invocation.control.cancellation.clone());

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

    let aggregate = collector.finish(report.clone());
    if let Some(staged) = &mut staged {
        write_log(staged, &aggregate.records)?;
        staged.sync()?;
    }
    if let Some(staged) = staged {
        staged.persist()?;
    }
    if format == Format::Ndjson {
        rendering::render_responder_complete(report, stream)?;
    }
    invocation.check()?;

    match format {
        Format::Ndjson => Ok(()),
        Format::Text => {
            let published =
                output::envelope::Published::<super::output::ResponderReport>::from(aggregate);
            rendering::render_responder_text(invocation, &published.result)
        }
        Format::Json => crate::rendering::emit_published(
            invocation,
            output::contract::Command::DifferentialResponder,
            output::envelope::Published::<super::output::ResponderReport>::from(aggregate),
        ),
        other => other.unreachable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::Spec as _;
    use crate::invocation::{Invocation, StreamEncoder};
    use crate::output::contract::Command;
    use clap::Parser as _;
    use lib::canary;
    use packetcraftr_core::clock::{Clock, SystemClock};
    use std::io::Write;
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn cancelled_responder_publishes_receptions() {
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

    fn parsed_args(port: u16, idle_ms: u64, duration_ms: u64, log: &std::path::Path) -> Args {
        Wrap::try_parse_from([
            "test",
            "--bind",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--token",
            &"42".repeat(16),
            "--idle-ms",
            &idle_ms.to_string(),
            "--max-duration-ms",
            &duration_ms.to_string(),
            "--log-file",
            log.to_str().expect("log path is UTF-8"),
        ])
        .expect("arguments parse")
        .args
    }

    fn free_port() -> u16 {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
        socket.local_addr().expect("address").port()
    }

    fn probe() -> Vec<u8> {
        canary::build_probe(&[0x42; 16], 1, 7, 256)
    }

    fn probe_until_answered(port: u16, finished: impl Fn() -> bool) -> bool {
        let probe_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("probe socket");
        probe_socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");
        let payload = probe();
        let mut buffer = [0_u8; 128];
        let probe_deadline = SystemClock.now() + Duration::from_secs(3);
        while SystemClock.now() < probe_deadline && !finished() {
            probe_socket
                .send_to(&payload, (Ipv4Addr::LOCALHOST, port))
                .expect("probe sends");
            if probe_socket.recv_from(&mut buffer).is_ok() {
                return true;
            }
        }
        false
    }

    fn holds_probe_record(contents: &str) -> bool {
        let expected = lib::hex(&canary::payload_sha256(&probe()));
        contents
            .lines()
            .filter_map(|line| serde_json::from_str::<lib::ReceptionRecord>(line).ok())
            .any(|record| record.attempt_seq == 7 && record.payload_sha256 == expected)
    }

    #[derive(Clone, Default)]
    struct Stdout(Arc<Mutex<Vec<u8>>>);

    impl Stdout {
        fn events(&self) -> Vec<String> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|line| {
                    let record: serde_json::Value = serde_json::from_str(line).unwrap();
                    record["event"].as_str().unwrap().to_owned()
                })
                .collect()
        }
    }

    impl Write for Stdout {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct ClosedStdout;

    impl Write for ClosedStdout {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn ndjson(writer: impl Write + Send + 'static, deadline: Option<Duration>) -> Invocation {
        Invocation::new(
            Format::Ndjson,
            StreamEncoder::new(Command::DifferentialResponder, writer),
            deadline,
            Default::default(),
            None,
        )
    }

    fn run_with_traffic(
        log: &std::path::Path,
        idle_ms: u64,
        duration_ms: u64,
        stdout: Stdout,
        deadline_ms: Option<u64>,
        after_answer: impl Fn(),
    ) -> Result<(), CliError> {
        for _ in 0..3 {
            let port = free_port();
            let arguments = parsed_args(port, idle_ms, duration_ms, log);
            let deadline = deadline_ms
                .map(Duration::from_millis)
                .or_else(|| arguments.publication_duration());
            let invocation = ndjson(stdout.clone(), deadline);
            let handle = thread::spawn(move || run(&invocation, arguments));
            let answered = probe_until_answered(port, || handle.is_finished());
            if answered {
                after_answer();
            }
            let outcome = handle.join().expect("responder thread finishes");
            if answered {
                return outcome;
            }
            let _ = std::fs::remove_file(log);
            stdout.0.lock().unwrap().clear();
        }
        panic!("responder never answered across retries");
    }

    #[test]
    fn duration_expiry_publishes_empty_log_and_report() {
        let directory = tempfile::tempdir().expect("test directory");
        for format in [Format::Text, Format::Json, Format::Ndjson] {
            let log = directory.path().join(format!("{format:?}.jsonl"));
            let arguments = parsed_args(free_port(), 0, 100, &log);
            let stdout = Stdout::default();
            let invocation = Invocation::new(
                format,
                StreamEncoder::new(Command::DifferentialResponder, stdout.clone()),
                arguments.publication_duration(),
                Default::default(),
                None,
            );

            run(&invocation, arguments).expect("duration stop succeeds");
            assert_eq!(std::fs::read_to_string(&log).expect("log published"), "");
            if format == Format::Ndjson {
                assert_eq!(stdout.events(), ["complete"]);
            }
        }
    }

    #[test]
    fn duration_expiry_preserves_receptions() {
        let directory = tempfile::tempdir().expect("test directory");
        let log = directory.path().join("responder-log.jsonl");
        let stdout = Stdout::default();

        run_with_traffic(&log, 0, 1000, stdout.clone(), None, || {})
            .expect("duration stop succeeds");

        let contents = std::fs::read_to_string(&log).expect("log published");
        assert!(holds_probe_record(&contents), "log contents: {contents}");
        assert_eq!(stdout.events().last().map(String::as_str), Some("complete"));
    }

    #[test]
    fn blocked_live_output_does_not_send_a_reply_after_duration() {
        struct BlockedWriter {
            entered: std::sync::mpsc::Sender<()>,
            release: Option<std::sync::mpsc::Receiver<()>>,
        }

        impl Write for BlockedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if let Some(release) = self.release.take() {
                    self.entered.send(()).unwrap();
                    release.recv().unwrap();
                }
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let directory = tempfile::tempdir().expect("test directory");
        let log = directory.path().join("responder-log.jsonl");
        let port = free_port();
        let arguments = parsed_args(port, 0, 500, &log);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let runtime = packetcraftr::runtime::Runtime::new(1).unwrap();
        let stream = crate::output::stream::StreamEncoder::new_bounded(
            Command::DifferentialResponder,
            BlockedWriter {
                entered: entered_tx,
                release: Some(release_rx),
            },
            &runtime,
            Duration::from_secs(1),
        )
        .unwrap();
        let invocation = Invocation::new(
            Format::Ndjson,
            stream.into(),
            arguments.publication_duration(),
            Default::default(),
            None,
        );
        let handle = thread::spawn(move || run(&invocation, arguments));
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let entered_deadline = SystemClock.now() + Duration::from_secs(2);
        let mut entered = false;
        while SystemClock.now() < entered_deadline && !handle.is_finished() {
            socket
                .send_to(&probe(), (Ipv4Addr::LOCALHOST, port))
                .unwrap();
            if entered_rx.recv_timeout(Duration::from_millis(20)).is_ok() {
                entered = true;
                break;
            }
        }
        assert!(entered, "live event reached the blocked output");
        thread::sleep(Duration::from_millis(650));
        let stop_deadline = SystemClock.now() + Duration::from_millis(250);
        while !handle.is_finished() && SystemClock.now() < stop_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let stopped_before_release = handle.is_finished();
        release_tx.send(()).unwrap();
        let mut reply = [0_u8; 128];
        assert!(socket.recv_from(&mut reply).is_err(), "no late UDP reply");
        assert!(
            handle.join().unwrap().is_err(),
            "blocked output is reported"
        );
        assert!(stopped_before_release, "live output exceeded the duration");
        assert!(holds_probe_record(&std::fs::read_to_string(log).unwrap()));
    }

    #[test]
    fn expired_publication_budget_keeps_published_log_without_completion() {
        let directory = tempfile::tempdir().expect("test directory");
        let log = directory.path().join("responder-log.jsonl");
        let stdout = Stdout::default();

        let outcome = run(
            &ndjson(stdout.clone(), Some(Duration::from_millis(1))),
            parsed_args(free_port(), 0, 100, &log),
        );

        assert!(outcome.is_err(), "the expired publication stays reported");
        assert_eq!(std::fs::read_to_string(&log).expect("log published"), "");
        assert!(!stdout.events().iter().any(|event| event == "complete"));
    }

    #[test]
    fn failed_completion_write_keeps_published_log() {
        let directory = tempfile::tempdir().expect("test directory");
        let log = directory.path().join("responder-log.jsonl");

        let outcome = run(
            &ndjson(ClosedStdout, None),
            parsed_args(free_port(), 0, 50, &log),
        );

        assert!(outcome.is_err(), "the failed write stays reported");
        assert_eq!(std::fs::read_to_string(&log).expect("log published"), "");
    }

    #[test]
    fn completion_follows_publication() {
        let directory = tempfile::tempdir().expect("test directory");
        let log = directory.path().join("responder-log.jsonl");
        let stdout = Stdout::default();

        run_with_traffic(&log, 20, 30_000, stdout.clone(), None, || {})
            .expect("idle stop succeeds");

        assert!(holds_probe_record(&std::fs::read_to_string(&log).unwrap()));
        assert_eq!(stdout.events().last().map(String::as_str), Some("complete"));
    }

    #[test]
    fn publication_conflict_keeps_existing_log_without_completion() {
        let directory = tempfile::tempdir().expect("test directory");
        let log = directory.path().join("responder-log.jsonl");
        let stdout = Stdout::default();

        let outcome = run_with_traffic(&log, 0, 1000, stdout.clone(), None, || {
            std::fs::write(&log, "existing").expect("competing log");
        });

        assert!(outcome.is_err(), "the conflict stays reported");
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "existing");
        assert!(!stdout.events().iter().any(|event| event == "complete"));
    }

    fn try_cancelled_run(log: &std::path::Path, _attempt: usize) -> bool {
        let port = free_port();
        let arguments = parsed_args(port, 0, 30_000, log);
        let invocation = Invocation::new(
            Format::Text,
            StreamEncoder::new(Command::DifferentialResponder, Vec::<u8>::new()),
            None,
            Default::default(),
            None,
        );
        let cancellation = invocation.control.cancellation.clone();
        let handle = thread::spawn(move || run(&invocation, arguments));

        if !probe_until_answered(port, || handle.is_finished()) {
            cancellation.cancel();
            let _ = handle.join();
            return false;
        }
        cancellation.cancel();
        let outcome = handle.join().expect("responder thread finishes");
        assert!(outcome.is_err(), "cancellation reports as an error");

        let contents = std::fs::read_to_string(log).expect("reception log was published");
        assert!(
            holds_probe_record(&contents),
            "log holds the reception record: {contents}"
        );
        true
    }
}
