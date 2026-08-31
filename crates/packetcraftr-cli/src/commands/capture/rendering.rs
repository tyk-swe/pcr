// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core::error::Kind;

use std::io::{self, Write};

use packetcraftr::{
    analysis::pcap::{
        self as capture, Interface, Limits, PcapNgOptions, PcapOptions, TimestampResolution, Writer,
    },
    netio as net, output,
};

use packetcraftr::policy::CaptureBudget;

use super::execution::{self, Session, shutdown_after_error};
use crate::errors::CliError;
use crate::rendering::{
    SourceCaptureWriter, StreamEncoder, captured_frame_text, render_diagnostics_stderr,
    render_diagnostics_text, stdout_error, stream_capture_error, write_plain_line,
    write_stdout_line, write_summary_line,
};

pub(super) fn render_text<C: net::capture::Session>(
    session: Session<'_, C>,
) -> Result<(), CliError> {
    let filtered = session.selector.is_some();
    let outcome = execution::run(session, |frame, source_frame| {
        let frame = output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
        write_stdout_line(format_args!(
            "{source_frame}: {}",
            captured_frame_text(&frame)
        ))
    })?;
    if filtered {
        write_summary_line(format_args!(
            "matched {} of {} captured frame(s), {} byte(s)",
            outcome.stats.packets_completed, outcome.stats.packets_attempted, outcome.stats.bytes
        ))?;
    } else {
        write_summary_line(format_args!(
            "captured {} frame(s), {} byte(s)",
            outcome.stats.packets_completed, outcome.stats.bytes
        ))?;
    }
    render_diagnostics_text(&outcome.diagnostics)
}

pub(super) fn render_hex<C: net::capture::Session>(
    session: Session<'_, C>,
) -> Result<(), CliError> {
    let outcome = execution::run(session, |frame, _| {
        let frame = output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
        write_plain_line(format_args!("{}", frame.bytes_hex()))
    })?;
    render_diagnostics_stderr(&outcome.diagnostics)
}

pub(super) fn render_stream<C: net::capture::Session>(
    session: Session<'_, C>,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let outcome = execution::run(session, |frame, source_frame| {
        let event = output::capture::Event::try_from_frame(source_frame, frame)
            .map_err(CliError::classified)?;
        Ok(stream.emit_data(event, Vec::new())?)
    })?;
    Ok(stream.complete_with_stats(
        output::capture::Event::Complete,
        outcome.diagnostics,
        outcome.stats,
    )?)
}

pub(super) fn render_capture<C: net::capture::Session>(
    mut session: Session<'_, C>,
    format: capture::Format,
) -> Result<(), CliError> {
    let source_id = Some(session.capture.metadata().interface.index);
    let stdout = io::stdout();
    let (mut writer, description) = match initialize_writer(
        stdout.lock(),
        format,
        session.capture.metadata(),
        session.budget,
    ) {
        Ok(initialized) => initialized,
        Err(error) => return Err(shutdown_after_error(&mut session.capture, error)),
    };
    let outcome = execution::run(session, |frame, _| {
        writer
            .write_source_frame(source_id, description.clone(), frame)
            .map_err(|source| stream_capture_error("write capture output failed", source))
    })?;
    writer
        .into_inner()
        .flush()
        .map_err(|source| stdout_error("flush stdout failed", source))?;
    render_diagnostics_stderr(&outcome.diagnostics)
}

fn initialize_writer<W: Write>(
    destination: W,
    format: capture::Format,
    metadata: &net::capture::Metadata,
    budget: CaptureBudget,
) -> Result<(SourceCaptureWriter<W>, Interface), CliError> {
    let snap_len = u32::try_from(metadata.snap_length).map_err(|_| {
        CliError::new(Kind::Io,
            "initialize capture output failed: backend snapshot length exceeds the capture-file domain",
        )
    })?;

    let description = Interface {
        link_type: metadata.link_type,
        snap_len,
        timestamp_resolution: TimestampResolution::Decimal(9),
        timestamp_offset: 0,
    };
    let stream_limits = Limits {
        max_frames: budget.max_frames(),
        max_bytes: budget.max_bytes(),
    };
    let writer = match format {
        capture::Format::Pcap => Writer::pcap_with_options(
            destination,
            metadata.link_type,
            PcapOptions {
                snap_len: metadata.snap_length,
                max_size: metadata.snap_length,
                stream_limits,
                ..PcapOptions::default()
            },
        ),
        capture::Format::PcapNg => Writer::pcapng_with_options(
            destination,
            PcapNgOptions {
                max_size: pcapng_max_size(metadata.snap_length)?,
                stream_limits,
                ..PcapNgOptions::default()
            },
        ),
    }
    .map_err(|source| stream_capture_error("initialize capture output failed", source))?;
    let mut writer = SourceCaptureWriter::new(writer);
    writer
        .add_source_interface(Some(metadata.interface.index), description.clone())
        .map_err(|source| stream_capture_error("initialize capture output failed", source))?;
    Ok((writer, description))
}

fn pcapng_max_size(snap_length: usize) -> Result<usize, CliError> {
    snap_length.checked_add(47).ok_or_else(|| {
        CliError::new(Kind::Io,
            "initialize capture output failed: backend snapshot length cannot fit a PCAPNG packet block",
        )
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, UNIX_EPOCH};

    use packetcraftr::core;
    use packetcraftr::core::frame::{Frame, LinkType};
    use serde_json::Value;

    use super::*;
    use crate::filtering::{self, Capabilities, FrameSelector};
    use crate::rendering::ndjson_test_support::{assert_contiguous, stream};

    struct FakeSession {
        metadata: net::capture::Metadata,
        frames: VecDeque<Result<net::capture::Captured, net::Error>>,
        shutdown_error: Option<net::Error>,
        shutdowns: Arc<AtomicUsize>,
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
                shutdowns: Arc::new(AtomicUsize::new(0)),
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
            self.shutdowns.fetch_add(1, Ordering::Relaxed);
            match self.shutdown_error.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        fn statistics(&self) -> net::capture::Statistics {
            net::capture::Statistics::default()
        }
    }

    fn settings() -> (net::capture::Limits, CaptureBudget) {
        (net::capture::Limits::default(), budget(8, 8))
    }

    fn budget(max_frames: u64, max_bytes: u64) -> CaptureBudget {
        CaptureBudget::new(&packetcraftr::policy::Policy {
            max_packets_per_operation: max_frames,
            max_bytes_per_operation: max_bytes,
            ..packetcraftr::policy::Policy::default()
        })
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
        let budget = budget(1, 96);

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
        let (stream, output) = stream(output::contract::Command::Capture);
        render_stream(
            Session {
                capture: FakeSession::with_frames(2),
                timeout: Duration::from_secs(1),
                limits,
                budget,
                selector: None,
            },
            &stream,
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
        let registry = core::protocol::builtin::registry();
        let filter =
            filtering::compile("frame.number == 3", &registry, Capabilities::frames_only())
                .expect("frame-number selector must compile");
        let selector = FrameSelector::new(registry, filter, 1);
        let (limits, budget) = settings();
        let (stream, output) = stream(output::contract::Command::Capture);

        render_stream(
            Session {
                capture: FakeSession::with_frames(3),
                timeout: Duration::from_secs(1),
                limits,
                budget,
                selector: Some(&selector),
            },
            &stream,
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

    /// The byte budget stops the capture where the frame budget still had
    /// room, and the records emitted up to that point stay a clean prefix.
    #[test]
    fn capture_byte_budget_stops_the_stream_and_shuts_the_session_down() {
        let limits = net::capture::Limits::default();
        let capture = FakeSession::with_frames(4);
        let shutdowns = Arc::clone(&capture.shutdowns);
        let (stream, output) = stream(output::contract::Command::Capture);

        let error = render_stream(
            Session {
                capture,
                timeout: Duration::from_secs(1),
                limits,
                budget: budget(8, 2),
                selector: None,
            },
            &stream,
        )
        .expect_err("the byte budget must stop the capture");

        assert_eq!(error.classification.code, "policy.byte_limit");
        assert_eq!(shutdowns.load(Ordering::Relaxed), 1);

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["result"]["source_frame"], 1);
        assert_eq!(records[1]["result"]["source_frame"], 2);
        assert_matches_published_schema(&records);
    }

    /// A spent frame budget is the capture finishing, not the capture failing.
    #[test]
    fn capture_frame_budget_ends_the_stream_without_an_error() {
        let limits = net::capture::Limits::default();
        let capture = FakeSession::with_frames(4);
        let shutdowns = Arc::clone(&capture.shutdowns);
        let (stream, output) = stream(output::contract::Command::Capture);

        render_stream(
            Session {
                capture,
                timeout: Duration::from_secs(1),
                limits,
                budget: budget(1, 64),
                selector: None,
            },
            &stream,
        )
        .expect("a spent frame budget is a normal end");

        assert_eq!(shutdowns.load(Ordering::Relaxed), 1);

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["result"]["source_frame"], 1);
        assert_eq!(records[1]["result"]["event"], "complete");
        assert_eq!(records[1]["stats"]["packets_attempted"], 1);
        assert_eq!(records[1]["stats"]["packets_completed"], 1);
        assert_matches_published_schema(&records);
    }

    /// A byte counter that would wrap is a budget the capture cannot pay from,
    /// not an internal fault: it has to read as the same limit refusal.
    #[test]
    fn capture_byte_counter_overflow_reads_as_the_byte_limit() {
        let limits = net::capture::Limits::default();
        let mut budget = budget(8, u64::MAX);
        budget
            .account(u64::MAX)
            .expect("the first charge fills the counter exactly");

        let capture = FakeSession::with_frames(1);
        let shutdowns = Arc::clone(&capture.shutdowns);
        let (stream, output) = stream(output::contract::Command::Capture);

        let error = render_stream(
            Session {
                capture,
                timeout: Duration::from_secs(1),
                limits,
                budget,
                selector: None,
            },
            &stream,
        )
        .expect_err("the next byte cannot be charged");

        assert_eq!(error.classification.code, "policy.byte_limit");
        assert_ne!(error.exit_code(), 70);
        assert_eq!(shutdowns.load(Ordering::Relaxed), 1);
        assert!(output.records().is_empty());
    }

    #[test]
    fn capture_runtime_and_cleanup_failure_keep_primary_at_next_position() {
        let (limits, budget) = settings();
        let mut capture = FakeSession::with_frames(2);
        capture.frames.push_back(Err(net::Error::Capture {
            message: "primary receive failure".to_owned(),
            source: None,
        }));
        capture.shutdown_error = Some(net::Error::Capture {
            message: "cleanup failure".to_owned(),
            source: None,
        });
        let (stream, output) = stream(output::contract::Command::Capture);

        let error = render_stream(
            Session {
                capture,
                timeout: Duration::from_secs(1),
                limits,
                budget,
                selector: None,
            },
            &stream,
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
