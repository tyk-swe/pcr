// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(packetcraftr_test_procfs)]

use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, UNIX_EPOCH};

use packetcraftr_core::build::Builder;
use packetcraftr_core::capture_file::{Format, Writer};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};

mod common;

struct Running {
    child: Child,
    stdout: tempfile::NamedTempFile,
}

impl Running {
    fn start(arguments: &[&str]) -> Self {
        Self::start_with_stdout_pipe(arguments, false)
    }

    fn start_with_stdout_pipe(arguments: &[&str], piped: bool) -> Self {
        let stdout = tempfile::NamedTempFile::new().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(if piped {
                Stdio::piped()
            } else {
                Stdio::from(stdout.reopen().unwrap())
            })
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

    fn intercepts_sigint(&self) -> bool {
        std::fs::read_to_string(format!("/proc/{}/status", self.child.id()))
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("SigCgt:"))
            .is_some_and(|mask| u64::from_str_radix(mask.trim(), 16).unwrap() & 2 != 0)
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

    fn signal_and_wait(&mut self, name: &str) {
        let tasks = format!("/proc/{}/task", self.child.id());
        self.wait_until(|_| {
            std::fs::read_dir(&tasks).unwrap().any(|entry| {
                std::fs::read_to_string(entry.unwrap().path().join("comm"))
                    .is_ok_and(|name| name.trim() == "ctrl-c")
            })
        });
        let worker = std::fs::read_dir(tasks)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|task| {
                std::fs::read_to_string(task.join("comm")).is_ok_and(|name| name.trim() == "ctrl-c")
            })
            .expect("signal worker must exist");
        let parked = || {
            std::fs::read_to_string(worker.join("wchan"))
                .unwrap()
                .contains("futex")
        };
        let switches = || {
            std::fs::read_to_string(worker.join("status"))
                .unwrap()
                .lines()
                .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:"))
                .expect("worker switch count must exist")
                .trim()
                .parse::<u64>()
                .unwrap()
        };
        // ctrlc 3.5.2 parks this dedicated worker in sem_wait between callbacks.
        // A new voluntary switch back into that wait observes callback completion;
        // the main thread stays blocked on the input/output controlled by the test.
        self.wait_until(|_| parked());
        let before = switches();
        self.signal(name);
        self.wait_until(|_| switches() > before && parked());
    }

    fn finish(&mut self) -> Output {
        use std::io::Read;
        let stdout_worker = self.child.stdout.take().map(|mut pipe| {
            let mut file = self.stdout.reopen().unwrap();
            std::thread::spawn(move || std::io::copy(&mut pipe, &mut file))
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "interrupted child did not stop");
            std::thread::sleep(Duration::from_millis(10));
        };
        if let Some(worker) = stdout_worker {
            worker.join().unwrap().unwrap();
        }
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
fn cancellation_during_aggregate_json_publication_keeps_one_complete_document() {
    common::require_procfs();
    let mut capture = tempfile::NamedTempFile::new().unwrap();
    let builder = Builder::new(packetcraftr_core::protocol::builtin::registry());
    {
        let mut writer = Writer::new(&mut capture, Format::Pcap, LinkType::IPV4).unwrap();
        for source_port in 10_000..11_000 {
            let mut packet = Packet::new();
            packet
                .push(Ipv4 {
                    source: Ipv4Addr::new(192, 0, 2, 1),
                    destination: Ipv4Addr::new(192, 0, 2, 2),
                    ..Ipv4::default()
                })
                .push(Udp {
                    source_port,
                    destination_port: 9,
                    ..Udp::default()
                });
            let built = builder
                .build(packet, Default::default(), Default::default())
                .unwrap();
            writer
                .write_frame(&Frame::new(UNIX_EPOCH, LinkType::IPV4, built.bytes).unwrap())
                .unwrap();
        }
        writer.flush().unwrap();
    }
    for signal in ["INT", "TERM"] {
        let mut process = Running::start_with_stdout_pipe(
            &[
                "--output",
                "json",
                "stats",
                common::path_text(capture.path()),
                "--top",
                "1000",
            ],
            true,
        );
        // Observe the blocked write itself so the signal always lands after
        // publication starts.
        process.wait_until(|p| {
            std::fs::read_to_string(format!("/proc/{}/wchan", p.child.id()))
                .unwrap()
                .contains("pipe_write")
        });
        process.signal_and_wait(signal);
        let output = process.finish();
        assert_eq!(output.status.code(), Some(130), "{signal}: {output:?}");
        let document = common::parse_json(&output);
        assert_eq!(
            document["result"]["conversations"]
                .as_array()
                .unwrap()
                .len(),
            1000
        );
        assert!(document.get("error").is_none());
        assert!(String::from_utf8_lossy(&output.stderr).contains("io.cancelled"));
    }
}

#[test]
fn offline_fuzz_cancels_without_a_success_report_in_every_format() {
    common::require_procfs();
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
            process.wait_until(Running::intercepts_sigint);
            std::thread::sleep(Duration::from_millis(100));
            process.signal(signal);
            let output = process.finish();
            assert_eq!(output.status.code(), Some(130), "{format}: {output:?}");
            match format {
                "json" => assert_eq!(common::parse_json(&output)["error"]["code"], "io.cancelled"),
                "ndjson" => {
                    let records = common::parse_ndjson(&output);
                    common::assert_contiguous(&records);
                    if records.last().unwrap()["event"] == "error" {
                        assert_eq!(records.last().unwrap()["error"]["code"], "io.cancelled");
                    } else {
                        assert!(records.iter().all(|record| record["event"] == "case"));
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        assert!(
                            stderr.contains("error[io.stdout]: NDJSON stream is incomplete"),
                            "{stderr}"
                        );
                        assert!(stderr.contains("operation cancelled"), "{stderr}");
                    }
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
fn a_repeated_interrupt_removes_staged_output_before_exiting() {
    common::require_procfs();
    let mut seed = tempfile::NamedTempFile::new().unwrap();
    {
        let mut writer = Writer::new(&mut seed, Format::Pcap, LinkType::IPV4).unwrap();
        writer
            .write_frame(&Frame::new(UNIX_EPOCH, LinkType::IPV4, b"seed".to_vec()).unwrap())
            .unwrap();
        writer.flush().unwrap();
    }
    let seed = common::path_text(seed.path());
    for command in ["merge", "rewrite", "export"] {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("out.pcapng");
        let destination = common::path_text(&destination);
        // Stdin stays open, so the command blocks in its input after staging.
        let arguments: &[&str] = match command {
            "merge" => &["merge", "--write", destination, seed, "-"],
            "rewrite" => &[
                "rewrite",
                "-",
                "--write",
                destination,
                "--set",
                "ipv4.ttl=64",
            ],
            _ => &[
                "export",
                "-",
                "--write",
                destination,
                "--filter",
                "frame.number > 0",
            ],
        };
        let mut process = Running::start(arguments);
        process.wait_until(|p| {
            p.intercepts_sigint()
                && std::fs::read_to_string(format!("/proc/{}/wchan", p.child.id()))
                    .unwrap()
                    .contains("pipe_read")
                && std::fs::read_dir(directory.path()).unwrap().count() == 1
        });
        process.signal("INT");
        std::thread::sleep(Duration::from_millis(100));
        process.signal("INT");
        let output = process.finish();
        assert_eq!(output.status.code(), Some(130), "{command}: {output:?}");
        let leftovers: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(leftovers.is_empty(), "{command}: {leftovers:?}");
    }
}

#[test]
fn http2_cancellation_emits_one_error_without_complete() {
    common::require_procfs();
    for signal in ["INT", "TERM"] {
        let bytes = common::http2_capture::capture_bytes(&[common::http2_capture::multiplexed(80)]);
        let mut process = Running::start(&["--output", "ndjson", "http2", "-"]);
        process
            .child
            .stdin
            .as_mut()
            .expect("stdin must be piped")
            .write_all(&bytes)
            .expect("capture bytes must write");
        process
            .child
            .stdin
            .as_mut()
            .unwrap()
            .flush()
            .expect("capture bytes must flush");
        process.wait_until(|p| {
            let emitted = std::fs::read(p.stdout.path()).unwrap_or_default();
            let complete_frame_line = emitted.split(|b| *b == b'\n').any(|line| {
                !line.is_empty()
                    && serde_json::from_slice::<serde_json::Value>(line)
                        .is_ok_and(|record| record["event"] == "http2_frame")
            });
            complete_frame_line
                && p.intercepts_sigint()
                && std::fs::read_to_string(format!("/proc/{}/wchan", p.child.id()))
                    .is_ok_and(|wchan| wchan.contains("pipe_read"))
        });
        process.signal(signal);
        std::thread::sleep(Duration::from_millis(100));
        process.child.stdin.take();
        let output = process.finish();
        assert_eq!(output.status.code(), Some(130), "{signal}: {output:?}");
        let records = common::parse_ndjson(&output);
        common::assert_contiguous(&records);
        let errors: Vec<_> = records
            .iter()
            .filter(|record| record["event"] == "error")
            .collect();
        assert_eq!(errors.len(), 1, "{signal}: {records:?}");
        assert_eq!(errors[0]["error"]["code"], "io.cancelled");
        assert!(
            records.iter().all(|record| record["event"] != "complete"),
            "{signal}: cancelled analysis must not complete"
        );
    }
}
