// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::invocation::Invocation;
use packetcraftr_core::error::{Classification, Coordinate};
use std::{
    cell::RefCell,
    io::{self, Write},
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct Writer {
    bytes: Arc<Mutex<Vec<u8>>>,
    fail: bool,
}

impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut written = self.bytes.lock().unwrap();
        if self.fail && !written.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected pipe failure",
            ));
        }
        let count = if self.fail {
            bytes.len().min(3)
        } else {
            bytes.len()
        };
        written.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn invocation(format: Format, writer: Writer) -> Invocation {
    Invocation::new(
        format,
        StreamEncoder::new(Command::Build, writer),
        None,
        Default::default(),
        None,
    )
}

#[test]
fn generator_cancellation_maps_to_interrupt_status_after_diagnostic_write() {
    let invocation = invocation(Format::Text, Writer::default());
    invocation.cancellation.cancel();
    let error = invocation.cancellation.check().unwrap_err();
    let code = generation_exit(&invocation, Err(CliError::classified(error)), |error| {
        assert_eq!(error.classification.code, "io.cancelled");
        Ok(())
    });
    assert_eq!(code, ExitCode::from(CANCELLED_EXIT_CODE));
}

#[test]
fn generator_diagnostic_write_failure_precedes_cancellation_status() {
    let invocation = invocation(Format::Text, Writer::default());
    invocation.cancellation.cancel();
    let code = generation_exit(
        &invocation,
        Err(CliError::new(Kind::Io, "cancelled operation")),
        |_| Err(CliError::new(Kind::Io, "stderr closed")),
    );
    assert_eq!(code, ExitCode::from(5));
}

#[test]
fn error_handling_json_reporting_failure_keeps_original_diagnostics() {
    let invocation = invocation(Format::Json, Writer::default());
    let error = CliError::from_classification(
        Classification::new("packet.test", Kind::Packet, Some("repair input")),
        "original command failure",
        vec!["original cause".into()],
    )
    .with_context(Some(Coordinate::SourceFrame(9)));
    let code = command_failure_with(
        &invocation,
        Command::Build,
        error,
        |_, envelope| {
            let document = serde_json::to_value(envelope).unwrap();
            assert_eq!(document["error"]["context"]["source_frame"], 9);
            Err(CliError::wrapping(
                Kind::Io,
                "write stdout failed",
                &io::Error::other("closed pipe"),
            ))
        },
        |error| {
            assert!(error.message.contains("original command failure"));
            assert!(error.message.contains("write stdout failed"));
            assert!(error.causes.iter().any(|cause| cause == "original cause"));
            assert!(error.causes.iter().any(|cause| cause == "closed pipe"));
            assert_eq!(error.context(), Some(Coordinate::SourceFrame(9)));
            Ok(())
        },
    );
    assert_eq!(code, ExitCode::from(5));
}

#[test]
fn error_handling_json_after_publication_uses_stderr_and_prioritizes_output_failure() {
    for (cancelled, output_failed, expected) in
        [(false, false, 3), (true, false, 130), (true, true, 5)]
    {
        let invocation = invocation(Format::Json, Writer::default());
        invocation.begin_json().unwrap();
        if cancelled {
            invocation.cancellation.cancel();
        }
        let error = if output_failed {
            CliError::from_classification(
                Classification::new("io.stdout", Kind::Io, None),
                "write failed",
                Vec::new(),
            )
        } else {
            CliError::new(Kind::Packet, "late failure")
        };
        let reported = RefCell::new(false);
        let code = command_failure_with(
            &invocation,
            Command::Build,
            error,
            |_, _| panic!("must not append another JSON document"),
            |_| {
                *reported.borrow_mut() = true;
                Ok(())
            },
        );
        assert!(*reported.borrow());
        assert_eq!(code, ExitCode::from(expected));
    }
}

#[test]
fn error_handling_ndjson_cancellation_reports_one_terminal_record_or_io_failure() {
    for fail in [false, true] {
        let writer = Writer {
            fail,
            ..Default::default()
        };
        let invocation = invocation(Format::Ndjson, writer.clone());
        invocation.cancellation.cancel();
        let code = command_failure_with(
            &invocation,
            Command::Build,
            CliError::new(Kind::Io, "cancelled operation"),
            |_, _| panic!("NDJSON must not use aggregate JSON"),
            |error| {
                assert!(fail);
                assert!(error.message.contains("cancelled operation"));
                assert!(
                    error
                        .causes
                        .iter()
                        .any(|cause| cause == "injected pipe failure")
                );
                Ok(())
            },
        );
        assert_eq!(code, ExitCode::from(if fail { 5 } else { 130 }));
        assert!(!invocation.output.is_open());
        assert!(!invocation.output.is_complete());
        let before = writer.bytes.lock().unwrap().clone();
        if !fail {
            let document: serde_json::Value = serde_json::from_slice(&before).unwrap();
            assert_eq!(document["event"], "error");
        }
        command_failure_with(
            &invocation,
            Command::Build,
            CliError::new(Kind::Packet, "later failure"),
            |_, _| panic!("closed stream must not use aggregate JSON"),
            |_| Ok(()),
        );
        assert_eq!(*writer.bytes.lock().unwrap(), before);
    }
}

#[test]
fn error_handling_failed_ndjson_preserves_context_and_original_cause() {
    let writer = Writer {
        fail: true,
        ..Default::default()
    };
    let invocation = invocation(Format::Ndjson, writer.clone());
    assert!(
        invocation
            .output
            .emit_error(CliError::new(Kind::Packet, "first failure").output_error())
            .is_err()
    );
    invocation.cancellation.cancel();
    let error = CliError::from_classification(
        Classification::new("packet.test", Kind::Packet, None),
        "original failure",
        vec!["original cause".into()],
    )
    .with_context(Some(Coordinate::ProbeSequence(4)));
    let before = writer.bytes.lock().unwrap().clone();
    let code = command_failure_with(
        &invocation,
        Command::Build,
        error,
        |_, _| panic!("failed NDJSON must not use aggregate JSON"),
        |error| {
            assert_eq!(error.classification.code, "io.stdout");
            assert_eq!(error.context(), Some(Coordinate::ProbeSequence(4)));
            assert_eq!(error.causes, ["original failure", "original cause"]);
            Ok(())
        },
    );
    assert_eq!(code, ExitCode::from(5));
    assert_eq!(*writer.bytes.lock().unwrap(), before);
}
