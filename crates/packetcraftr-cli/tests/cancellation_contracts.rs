// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(target_os = "linux")]

use std::io::{Cursor, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, UNIX_EPOCH};

use packetcraftr_core::analysis::pcap::{Format, Reader, Writer};
use packetcraftr_core::frame::{Frame, LinkType};

mod support;

// Every process assertion has finite cleanup, including failures before stdin
// is released. Output files keep a generating child from blocking on stdout.
struct Running {
    child: Child,
    stdout: tempfile::NamedTempFile,
}

impl Running {
    fn start(arguments: &[&str]) -> Self {
        let stdout = tempfile::NamedTempFile::new().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(stdout.reopen().unwrap())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Self { child, stdout }
    }

    fn wait_until(&mut self, ready: impl Fn(&Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready(self) {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "child exited before readiness"
            );
            assert!(Instant::now() < deadline, "child did not become ready");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn signal(&self, name: &str) {
        assert!(
            Command::new("kill")
                .args(["-s", name, &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }

    fn finish(&mut self) -> Output {
        use std::io::Read;
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "interrupted child did not stop");
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut stderr = Vec::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        Output {
            status,
            stdout: std::fs::read(self.stdout.path()).unwrap(),
            stderr,
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn interrupted_capture_copy_and_selection_reject_later_records_and_eof() {
    for format in [Format::Pcap, Format::PcapNg] {
        let mut prefix = Vec::new();
        let mut writer = Writer::new(&mut prefix, format, LinkType::IPV4).unwrap();
        // A newline flushes the process stdout line buffer before more input.
        writer
            .write_frame(&Frame::new(UNIX_EPOCH, LinkType::IPV4, b"before\n".to_vec()).unwrap())
            .unwrap();
        writer.flush().unwrap();
        drop(writer);
        let mut later = Vec::new();
        let mut writer = Writer::new(&mut later, format, LinkType::IPV4).unwrap();
        writer
            .write_frame(&Frame::new(UNIX_EPOCH, LinkType::IPV4, b"after\n".to_vec()).unwrap())
            .unwrap();
        writer.flush().unwrap();
        drop(writer);
        let mut reader = Reader::new(Cursor::new(later)).unwrap();
        let later = loop {
            let record = reader.next_record().unwrap().unwrap();
            if record.frame.is_some() {
                break record.raw_bytes().to_vec();
            }
        };
        for filter in [false, true] {
            for eof in [false, true] {
                let mut args = vec!["--output", format.as_str(), "read", "-"];
                if filter {
                    args.extend(["--filter", "frame.number > 0"]);
                }
                let mut process = Running::start(&args);
                let mut stdin = process.child.stdin.take().unwrap();
                stdin.write_all(&prefix).unwrap();
                process.wait_until(|p| {
                    std::fs::read(p.stdout.path())
                        .unwrap()
                        .windows(6)
                        .any(|bytes| bytes == b"before")
                });
                process.signal(if eof { "TERM" } else { "INT" });
                // Allow the handler thread to consume the delivered signal
                // before releasing the blocked input read.
                std::thread::sleep(Duration::from_millis(100));
                if !eof {
                    let _ = stdin.write_all(&later);
                }
                drop(stdin);
                let output = process.finish();
                assert_eq!(output.status.code(), Some(130), "{args:?}: {output:?}");
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains("io.cancelled"),
                    "{output:?}"
                );
                assert!(
                    !output.stdout.windows(5).any(|bytes| bytes == b"after"),
                    "{output:?}"
                );
            }
        }
    }
}

#[test]
fn offline_fuzz_cancels_without_a_success_report_in_every_format() {
    for format in ["text", "json", "ndjson"] {
        for signal in ["INT", "TERM"] {
            let mut process = Running::start(&[
                "--output",
                format,
                "fuzz",
                "--packet",
                "ipv4(dst=192.0.2.1)",
                "--field",
                "0.ttl",
                "--strategy",
                "random",
                "--cases",
                "100000",
                "--max-cases",
                "100000",
            ]);
            // Wait for SIGINT interception before sending it. This avoids
            // mistaking default termination during startup for cancellation.
            process.wait_until(|p| {
                std::fs::read_to_string(format!("/proc/{}/status", p.child.id()))
                    .unwrap()
                    .lines()
                    .find_map(|line| line.strip_prefix("SigCgt:"))
                    .is_some_and(|mask| u64::from_str_radix(mask.trim(), 16).unwrap() & 2 != 0)
            });
            std::thread::sleep(Duration::from_millis(100));
            process.signal(signal);
            let output = process.finish();
            assert_eq!(output.status.code(), Some(130), "{format}: {output:?}");
            match format {
                "json" => assert_eq!(
                    support::parse_json(&output)["error"]["code"],
                    "io.cancelled"
                ),
                "ndjson" => {
                    let records = support::parse_ndjson(&output);
                    support::assert_contiguous(&records);
                    assert_eq!(records.last().unwrap()["error"]["code"], "io.cancelled");
                    assert!(!records.iter().any(|record| record["event"] == "complete"));
                }
                _ => {
                    assert!(String::from_utf8_lossy(&output.stderr).contains("io.cancelled"));
                    assert!(!String::from_utf8_lossy(&output.stdout).contains("fuzz completed"));
                }
            }
        }
    }
}

#[test]
fn commands_without_cooperative_checks_keep_normal_signal_termination() {
    for (signal, number) in [("INT", 2), ("TERM", 15)] {
        let mut process = Running::start(&["build"]);
        std::thread::sleep(Duration::from_millis(100));
        process.signal(signal);
        let output = process.finish();
        assert_eq!(output.status.signal(), Some(number), "{output:?}");
        assert!(output.stdout.is_empty());
    }
}
