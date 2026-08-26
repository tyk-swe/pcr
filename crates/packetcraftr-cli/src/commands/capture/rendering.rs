// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};
use std::time::Duration;

use packetcraftr::{
    analysis::pcap::{
        self as capture, Interface, Limits, PcapNgOptions, PcapOptions, TimestampResolution, Writer,
    },
    core, netio as net, output,
};

use super::execution::{self, Budget, shutdown_after_error};
use crate::errors::CliError;
use crate::filtering::FrameSelector;
use crate::rendering::{
    CaptureWriter, NdjsonStream, capture_file_format, captured_frame_text, emit_stderr_message,
    render_diagnostics_text, write_plain_line, write_stdout_line,
};

pub(super) fn render_text<C: net::capture::Session>(
    capture: C,
    timeout: Duration,
    limits: net::capture::Limits,
    budget: Budget,
    selector: Option<&FrameSelector>,
) -> Result<(), CliError> {
    let outcome = execution::run(
        capture,
        timeout,
        limits,
        budget,
        selector,
        |frame, source_frame| {
            let frame =
                output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
            write_stdout_line(format_args!(
                "{source_frame}: {}",
                captured_frame_text(&frame)
            ))
        },
    )?;
    if selector.is_some() {
        write_stdout_line(format_args!(
            "matched {} of {} captured frame(s), {} byte(s)",
            outcome.stats.packets_completed, outcome.stats.packets_attempted, outcome.stats.bytes
        ))?;
    } else {
        write_stdout_line(format_args!(
            "captured {} frame(s), {} byte(s)",
            outcome.stats.packets_completed, outcome.stats.bytes
        ))?;
    }
    render_diagnostics_text(&outcome.diagnostics)
}

pub(super) fn render_hex<C: net::capture::Session>(
    capture: C,
    timeout: Duration,
    limits: net::capture::Limits,
    budget: Budget,
    selector: Option<&FrameSelector>,
) -> Result<(), CliError> {
    let outcome = execution::run(capture, timeout, limits, budget, selector, |frame, _| {
        let frame = output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
        write_plain_line(format_args!("{}", frame.bytes_hex()))
    })?;
    render_diagnostics(&outcome.diagnostics)
}

pub(super) fn render_stream<C: net::capture::Session>(
    capture: C,
    timeout: Duration,
    limits: net::capture::Limits,
    budget: Budget,
    selector: Option<&FrameSelector>,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let outcome = execution::run(
        capture,
        timeout,
        limits,
        budget,
        selector,
        |frame, source_frame| {
            let event = output::capture::Event::try_from_frame(source_frame, frame)
                .map_err(CliError::classified)?;
            stream.emit_data(event, Vec::new())
        },
    )?;
    stream.complete_with_stats(
        output::capture::Event::Complete,
        outcome.diagnostics,
        outcome.stats,
    )
}

pub(super) fn render_capture<C: net::capture::Session>(
    mut capture: C,
    format: output::contract::Format,
    timeout: Duration,
    limits: net::capture::Limits,
    budget: Budget,
    selector: Option<&FrameSelector>,
) -> Result<(), CliError> {
    let format = match capture_file_format(format) {
        Ok(format) => format,
        Err(error) => return Err(shutdown_after_error(&mut capture, error)),
    };
    let source_id = Some(capture.metadata().interface.index);
    let stdout = io::stdout();
    let (mut writer, description) =
        match initialize_writer(stdout.lock(), format, capture.metadata(), budget) {
            Ok(initialized) => initialized,
            Err(error) => return Err(shutdown_after_error(&mut capture, error)),
        };
    let outcome = execution::run(capture, timeout, limits, budget, selector, |frame, _| {
        writer
            .write_source_frame(source_id, description.clone(), frame)
            .map_err(|source| CliError::new(5, format!("write capture output failed: {source}")))
    })?;
    writer
        .into_inner()
        .flush()
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))?;
    render_diagnostics(&outcome.diagnostics)
}

fn initialize_writer<W: Write>(
    destination: W,
    format: capture::Format,
    metadata: &net::capture::Metadata,
    budget: Budget,
) -> Result<(CaptureWriter<W>, Interface), CliError> {
    let snap_len = u32::try_from(metadata.snap_length).map_err(|_| {
        CliError::new(
            5,
            "initialize capture output failed: backend snapshot length exceeds the capture-file domain",
        )
    })?;
    let description = Interface {
        link_type: metadata.link_type,
        snap_len,
        timestamp_resolution: TimestampResolution::Decimal(9),
        timestamp_offset: 0,
    };
    let writer = match format {
        capture::Format::Pcap => Writer::pcap_with_options(
            destination,
            metadata.link_type,
            PcapOptions {
                snap_len: metadata.snap_length,
                max_size: metadata.snap_length,
                ..PcapOptions::default()
            },
        ),
        capture::Format::PcapNg => Writer::pcapng_with_options(
            destination,
            PcapNgOptions {
                max_size: pcapng_max_size(metadata.snap_length)?,
                ..PcapNgOptions::default()
            },
        ),
    }
    .map_err(|source| CliError::new(5, format!("initialize capture output failed: {source}")))?;
    let mut writer = CaptureWriter::for_source_interfaces(writer);
    writer
        .add_source_interface(Some(metadata.interface.index), description.clone())
        .map_err(|source| {
            CliError::new(5, format!("initialize capture output failed: {source}"))
        })?;
    writer
        .set_stream_limits(Limits {
            max_frames: budget.max_frames,
            max_bytes: budget.max_bytes,
        })
        .map_err(CliError::classified)?;
    Ok((writer, description))
}

fn pcapng_max_size(snap_length: usize) -> Result<usize, CliError> {
    snap_length.checked_add(47).ok_or_else(|| {
        CliError::new(
            5,
            "initialize capture output failed: backend snapshot length cannot fit a PCAPNG packet block",
        )
    })
}

fn render_diagnostics(diagnostics: &[core::diagnostic::Diagnostic]) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        emit_stderr_message(&format!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::time::UNIX_EPOCH;

    use packetcraftr::core::frame::{Frame, LinkType};
    use serde_json::Value;

    use super::*;
    use crate::filtering::{self, Capabilities};
    use crate::rendering::ndjson_test_support::{assert_contiguous, stream};

    struct FakeSession {
        metadata: net::capture::Metadata,
        frames: VecDeque<Result<net::capture::Captured, net::Error>>,
        shutdown_error: Option<net::Error>,
    }

    impl FakeSession {
        fn with_frames(count: usize) -> Self {
            let frames = (0..count)
                .map(|value| {
                    let byte = u8::try_from(value).expect("fixture byte fits");
                    let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, vec![byte])
                        .expect("fixture frame is valid");
                    Ok(net::capture::Captured::without_ingress_time(frame))
                })
                .collect();
            Self {
                metadata: net::capture::Metadata {
                    interface: net::interface::Id {
                        name: "fixture0".to_owned(),
                        index: 7,
                    },
                    link_type: LinkType::RAW,
                    snap_length: net::capture::Limits::default().snap_length,
                },
                frames,
                shutdown_error: None,
            }
        }
    }

    impl net::capture::Session for FakeSession {
        fn metadata(&self) -> &net::capture::Metadata {
            &self.metadata
        }

        fn wait_ready(&mut self, _timeout: Duration) -> Result<(), net::Error> {
            Ok(())
        }

        fn next_captured_frame(
            &mut self,
            _timeout: Duration,
        ) -> Result<Option<net::capture::Captured>, net::Error> {
            self.frames.pop_front().transpose()
        }

        fn shutdown(&mut self) -> Result<(), net::Error> {
            match self.shutdown_error.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        fn statistics(&self) -> net::capture::Statistics {
            net::capture::Statistics::default()
        }
    }

    fn settings() -> (net::capture::Limits, Budget) {
        (
            net::capture::Limits::default(),
            Budget {
                max_frames: 8,
                max_bytes: 8,
            },
        )
    }

    fn assert_matches_published_schema(records: &[Value]) {
        for record in records {
            crate::test_support::schema_validator()
                .validate(record)
                .expect("capture stream record must validate");
        }
    }

    #[test]
    fn capture_files_use_negotiated_session_metadata_at_the_snapshot_limit() {
        use std::io::Cursor;

        use packetcraftr::analysis::pcap::Reader;
        use packetcraftr::netio::capture::Session as _;

        let mut capture = FakeSession::with_frames(0);
        capture.metadata.link_type = LinkType::LINUX_SLL2;
        capture.metadata.snap_length = 96;
        let budget = Budget {
            max_frames: 1,
            max_bytes: 96,
        };

        for format in [capture::Format::Pcap, capture::Format::PcapNg] {
            let (mut writer, description) =
                initialize_writer(Vec::new(), format, capture.metadata(), budget)
                    .expect("capture writer must use negotiated metadata");
            writer
                .write_source_frame(
                    Some(capture.metadata.interface.index),
                    description,
                    Frame::new(
                        UNIX_EPOCH,
                        capture.metadata.link_type,
                        vec![0_u8; capture.metadata.snap_length],
                    )
                    .expect("snapshot-sized frame"),
                )
                .expect("snapshot-sized frame must fit its output container");

            let mut reader =
                Reader::new(Cursor::new(writer.into_inner())).expect("generated capture must open");
            assert!(reader.next_frame().expect("generated frame").is_some());
            assert_eq!(reader.interfaces()[0].link_type, capture.metadata.link_type);
            assert_eq!(reader.interfaces()[0].snap_len, 96);
        }
    }

    #[test]
    fn capture_stream_success_is_contiguous_and_terminal() {
        let (limits, budget) = settings();
        let (mut stream, output) = stream(output::contract::Command::Capture);
        render_stream(
            FakeSession::with_frames(2),
            Duration::from_secs(1),
            limits,
            budget,
            None,
            &mut stream,
        )
        .expect("fake capture succeeds");

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["result"]["source_frame"], 1);
        assert_eq!(records[1]["result"]["source_frame"], 2);
        assert_eq!(records[2]["result"]["event"], "complete");
        assert_eq!(records[2]["stats"]["packets_attempted"], 2);
        assert_eq!(records[2]["stats"]["packets_completed"], 2);
        assert_eq!(records[2]["stats"]["bytes"], 2);
        assert_matches_published_schema(&records);
        assert!(!stream.is_open());
    }

    #[test]
    fn capture_selector_preserves_the_retained_source_frame() {
        let registry = Arc::new(
            core::protocol::builtin::registry().expect("built-in registry must initialize"),
        );
        let filter =
            filtering::compile("frame.number == 3", &registry, Capabilities::frames_only())
                .expect("frame-number selector must compile");
        let selector = FrameSelector::new(registry, filter, 1);
        let (limits, budget) = settings();
        let (mut stream, output) = stream(output::contract::Command::Capture);

        render_stream(
            FakeSession::with_frames(3),
            Duration::from_secs(1),
            limits,
            budget,
            Some(&selector),
            &mut stream,
        )
        .expect("filtered fake capture succeeds");

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["result"]["source_frame"], 3);
        assert_eq!(records[1]["sequence"], 1);
        assert_eq!(records[1]["result"]["event"], "complete");
        assert_eq!(records[1]["stats"]["packets_attempted"], 3);
        assert_eq!(records[1]["stats"]["packets_completed"], 1);
        assert_eq!(records[1]["stats"]["bytes"], 3);
        assert_matches_published_schema(&records);
    }

    #[test]
    fn capture_runtime_and_cleanup_failure_keep_primary_at_next_position() {
        let (limits, budget) = settings();
        let mut capture = FakeSession::with_frames(2);
        capture.frames.push_back(Err(net::Error::Capture {
            message: "primary receive failure".to_owned(),
        }));
        capture.shutdown_error = Some(net::Error::Capture {
            message: "cleanup failure".to_owned(),
        });
        let (mut stream, output) = stream(output::contract::Command::Capture);

        let error = render_stream(
            capture,
            Duration::from_secs(1),
            limits,
            budget,
            None,
            &mut stream,
        )
        .expect_err("fake capture fails after two records");
        let primary_code = error.classification.code;
        assert!(error.message.contains("primary receive failure"));
        assert!(error.message.contains("cleanup failure"));
        stream.emit_error(error.output_error()).unwrap();
        let records: Vec<Value> = output.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 3);
        assert_eq!(records[2]["status"], "error");
        assert_eq!(records[2]["error"]["code"], primary_code);
        assert!(
            records[2]["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("cleanup failure"))
        );
        assert!(
            records
                .iter()
                .all(|record| record["result"]["event"] != "complete")
        );
        assert_matches_published_schema(&records);
    }
}
