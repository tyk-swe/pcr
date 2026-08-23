// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use packetcraftr::{
    analysis::pcap::{self as capture, Format, Limits, Reader, Writer},
    netio as net, output,
};

use crate::error::{CAPTURE_LIMIT, failure};
use crate::rendering::{
    CaptureWriter, NdjsonStream, capture_file_format, emit_aggregate_with_stats, spaced_hex,
    write_stdout_line,
};
use packetcraftr::BoundaryError;

type Selector<'a> = Option<&'a mut dyn packetcraftr::replay::Selector>;

pub(super) struct CaptureSettings {
    pub(super) format: output::contract::Format,
    pub(super) max_interfaces: usize,
}

pub(super) fn render_text(
    reader: &mut Reader<File>,
    options: &packetcraftr::replay::Options,
    selector: Selector<'_>,
    authorizer: &mut packetcraftr::replay::SystemAuthorizer,
    transmitter: &mut packetcraftr::replay::SystemTransmitter,
    clock: &mut packetcraftr::clock::SystemClock,
    filtered: bool,
) -> Result<(), BoundaryError> {
    let summary = packetcraftr::replay::run_with_selector(
        reader,
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        render_record,
    )
    .map_err(BoundaryError::from_error)?;
    if filtered {
        write_stdout_line(format_args!(
            "replayed {} of {} frame(s), {} byte(s), scheduled delay {:?}",
            summary.frames_transmitted,
            summary.frames_read,
            summary.bytes_transmitted,
            summary.scheduled_duration
        ))
    } else {
        write_stdout_line(format_args!(
            "replayed {} frame(s), {} byte(s), scheduled delay {:?}",
            summary.frames_transmitted, summary.bytes_transmitted, summary.scheduled_duration
        ))
    }
}

pub(super) fn render_aggregate(
    reader: &mut Reader<File>,
    options: &packetcraftr::replay::Options,
    selector: Selector<'_>,
    authorizer: &mut packetcraftr::replay::SystemAuthorizer,
    transmitter: &mut packetcraftr::replay::SystemTransmitter,
    clock: &mut packetcraftr::clock::SystemClock,
    requested_interface: net::interface::Id,
) -> Result<(), BoundaryError> {
    let started = Instant::now();
    let mut frames = Vec::new();
    let summary = packetcraftr::replay::run_with_selector(
        reader,
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        |evidence| {
            frames.push(output_frame(evidence)?);
            Ok(())
        },
    )
    .map_err(BoundaryError::from_error)?;
    let stats = stats(&summary, started.elapsed());
    let result = output::replay::Result::from_summary(
        summary,
        requested_interface,
        options.link_mode,
        frames,
    );
    emit_aggregate_with_stats(output::contract::Command::Replay, result, Vec::new(), stats)
}

pub(super) fn render_stream<R, A, T, C>(
    reader: &mut Reader<R>,
    options: &packetcraftr::replay::Options,
    selector: Selector<'_>,
    authorizer: &mut A,
    transmitter: &mut T,
    clock: &mut C,
    stream: &mut NdjsonStream,
) -> Result<(), BoundaryError>
where
    R: Read,
    A: packetcraftr::replay::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
{
    let started = Instant::now();
    let summary = packetcraftr::replay::run_with_selector(
        reader,
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        |evidence| render_stream_record(stream, evidence),
    )
    .map_err(BoundaryError::from_error)?;
    let stats = stats(&summary, started.elapsed());
    let result = output::replay::Result::from_summary(
        summary,
        options.interface.clone(),
        options.link_mode,
        Vec::new(),
    );
    stream.complete_with_stats(result, Vec::new(), stats)
}

pub(super) fn render_capture(
    reader: &mut Reader<File>,
    options: &packetcraftr::replay::Options,
    selector: Selector<'_>,
    authorizer: &mut packetcraftr::replay::SystemAuthorizer,
    transmitter: &mut packetcraftr::replay::SystemTransmitter,
    clock: &mut packetcraftr::clock::SystemClock,
    settings: CaptureSettings,
) -> Result<(), BoundaryError> {
    let format = capture_file_format(settings.format)?;
    let stdout = io::stdout();
    let mut writer = capture_writer(
        reader,
        stdout.lock(),
        format,
        options.limits,
        settings.max_interfaces,
    )?;
    packetcraftr::replay::run_with_selector(
        reader,
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        |evidence| render_capture_record(&mut writer, evidence),
    )
    .map_err(BoundaryError::from_error)?;
    writer.flush().map_err(BoundaryError::from_error)
}

fn output_frame(
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<output::replay::Frame, packetcraftr::replay::Error> {
    let source_index = evidence.source_index;
    output::replay::Frame::try_from_evidence(evidence).map_err(|source| {
        packetcraftr::replay::Error::output_at_source_index(source_index, source.to_string())
    })
}

fn render_record(
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let result = output_frame(evidence)?;
    write_stdout_line(format_args!(
        "{}: sent {} bytes via {} (index {}, {:?}) dlt={} {}",
        result.source_index,
        result.bytes_sent,
        result.interface.name,
        result.interface.index,
        result.link_mode,
        result.frame.link_type,
        spaced_hex(result.frame.bytes())
    ))
    .map_err(|source| {
        packetcraftr::replay::Error::output_at_source_index(result.source_index, source.to_string())
    })
}

fn render_stream_record(
    stream: &mut NdjsonStream,
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let source_index = evidence.source_index;
    let result = output_frame(evidence)?;
    stream.emit_data(result, Vec::new()).map_err(|error| {
        packetcraftr::replay::Error::output_at_source_index(source_index, error.to_string())
    })
}

fn capture_writer<W: Write>(
    reader: &Reader<File>,
    destination: W,
    format: Format,
    limits: packetcraftr::replay::Limits,
    max_interfaces: usize,
) -> Result<CaptureWriter<W>, BoundaryError> {
    let writer = match format {
        Format::Pcap => classic_writer(reader, destination, format, limits)?,
        Format::PcapNg => Writer::pcapng_with_options(
            destination,
            capture::PcapNgOptions {
                endianness: reader.endianness(),
                max_size: limits.max_frame_bytes,
                max_interfaces,
            },
        )
        .map_err(BoundaryError::from_error)?,
    };
    let mut writer = CaptureWriter::for_source_interfaces(writer);
    writer
        .set_stream_limits(Limits {
            max_frames: limits.max_frames,
            max_bytes: limits.max_bytes,
        })
        .map_err(BoundaryError::from_error)?;
    Ok(writer)
}

fn classic_writer<W: Write>(
    reader: &Reader<File>,
    destination: W,
    format: Format,
    limits: packetcraftr::replay::Limits,
) -> Result<Writer<W>, BoundaryError> {
    if reader.format() != Format::Pcap {
        return Err(BoundaryError::from_error(
            capture::Error::MetadataNotRepresentable {
                format,
                field: "pcapng replay evidence",
            },
        ));
    }
    let interface = reader.interfaces()[0].clone();
    let snap_length = usize::try_from(interface.snap_len).map_err(|_| {
        failure(
            CAPTURE_LIMIT,
            "capture snap length exceeds the platform size limit",
        )
    })?;
    Writer::pcap_with_options(
        destination,
        interface.link_type,
        capture::PcapOptions {
            endianness: reader.endianness(),
            timestamp_resolution: interface.timestamp_resolution,
            snap_len: snap_length,
            max_size: limits.max_frame_bytes,
        },
    )
    .map_err(BoundaryError::from_error)
}

fn render_capture_record<W: Write>(
    writer: &mut CaptureWriter<W>,
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let source_index = evidence.source_index;
    writer
        .write_source_frame(
            evidence.source_interface_id,
            evidence.capture_interface,
            evidence.frame,
        )
        .map_err(|source| {
            packetcraftr::replay::Error::output_at_source_index(source_index, source.to_string())
        })
}

fn stats(summary: &packetcraftr::replay::Summary, elapsed: Duration) -> output::envelope::Stats {
    output::envelope::Stats {
        packets_attempted: summary.frames_read,
        packets_completed: summary.frames_transmitted,
        bytes: summary.bytes_transmitted,
        elapsed,
        capture: net::capture::Statistics::default().into(),
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::io::{self, Cursor};
    use std::time::UNIX_EPOCH;

    use packetcraftr::core::error::Classified;
    use packetcraftr::core::frame::{Frame, LinkType};

    use super::*;
    use crate::error::{exit_code, test_classification};
    use crate::rendering::ndjson_test_support::{assert_contiguous, stream};

    #[derive(Default)]
    struct FakeAuthorizer {
        calls: usize,
        deny_on: Option<usize>,
    }

    impl packetcraftr::replay::Authorizer for FakeAuthorizer {
        fn authorize_operation(
            &mut self,
            _context: packetcraftr::replay::AuthorizationContext,
            _frame: &Frame,
            _mode: net::link::Mode,
        ) -> Result<(), packetcraftr::BoundaryError> {
            self.calls += 1;
            if self.deny_on == Some(self.calls) {
                return Err(packetcraftr::BoundaryError::new(
                    "fixture policy denied replay",
                    test_classification("policy.fixture_replay", Some("authorize the fixture")),
                    vec!["fixture domain cause".to_owned()],
                ));
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeTransmitter;

    impl packetcraftr::replay::Transmitter for FakeTransmitter {
        fn validate_interface(
            &mut self,
            interface: &net::interface::Id,
            _mode: net::link::Mode,
            _frame: &Frame,
        ) -> Result<net::interface::Id, net::Error> {
            Ok(interface.clone())
        }

        fn transmit(
            &mut self,
            interface: &net::interface::Id,
            _mode: net::link::Mode,
            frame: &Frame,
        ) -> Result<packetcraftr::replay::Transmission, net::Error> {
            Ok(packetcraftr::replay::Transmission {
                interface: interface.clone(),
                report: net::transmit::Submission::start()
                    .complete(frame.bytes().len(), frame.bytes().clone()),
            })
        }
    }

    #[derive(Default)]
    struct FakeClock;

    impl packetcraftr::clock::Clock for FakeClock {
        type Error = Infallible;

        fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct OnlyFrame(u64);

    impl packetcraftr::replay::Selector for OnlyFrame {
        fn select(
            &mut self,
            number: u64,
            _frame: &Frame,
        ) -> Result<bool, packetcraftr::BoundaryError> {
            Ok(number == self.0)
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture replay output failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn interface() -> net::interface::Id {
        net::interface::Id {
            name: "fixture0".to_owned(),
            index: 7,
        }
    }

    fn options() -> packetcraftr::replay::Options {
        packetcraftr::replay::Options {
            interface: interface(),
            link_mode: net::link::Mode::Auto,
            timing: packetcraftr::replay::Timing::Immediate,
            limits: packetcraftr::replay::Limits::default(),
        }
    }

    fn reader(frame_count: usize) -> Reader<Cursor<Vec<u8>>> {
        let mut writer = capture::Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
        for value in 0..frame_count {
            let byte = u8::try_from(value % 256).expect("fixture byte fits");
            let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, vec![byte]).unwrap();
            writer.write_frame(&frame).unwrap();
        }
        Reader::new(Cursor::new(writer.into_inner())).unwrap()
    }

    fn render_fixture(
        reader: &mut Reader<Cursor<Vec<u8>>>,
        selector: Selector<'_>,
        authorizer: &mut FakeAuthorizer,
        stream: &mut NdjsonStream,
    ) -> Result<(), BoundaryError> {
        render_stream(
            reader,
            &options(),
            selector,
            authorizer,
            &mut FakeTransmitter,
            &mut FakeClock,
            stream,
        )
    }

    #[test]
    fn replay_stream_success_is_contiguous_and_terminal() {
        let (mut stream, output) = stream(output::contract::Command::Replay);
        render_fixture(
            &mut reader(2),
            None,
            &mut FakeAuthorizer::default(),
            &mut stream,
        )
        .expect("fake replay succeeds");

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 3);
        assert_eq!(records[2]["result"]["frames_completed"], 2);
        assert!(!stream.is_open());
    }

    #[test]
    fn replay_domain_failure_after_two_records_uses_position_two() {
        let (mut stream, output) = stream(output::contract::Command::Replay);
        let mut authorizer = FakeAuthorizer {
            calls: 0,
            deny_on: Some(3),
        };
        let error = render_fixture(&mut reader(3), None, &mut authorizer, &mut stream)
            .expect_err("third fake replay authorization is denied");

        assert_eq!(exit_code(&error), 6);
        assert_eq!(error.classification().code, "policy.fixture_replay");
        assert_eq!(error.causes(), ["fixture domain cause"]);
        stream
            .emit_error(output::envelope::Error::classified(&error))
            .unwrap();

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records[2]["status"], "error");
        assert_eq!(records[2]["error"]["code"], "policy.fixture_replay");
        assert_eq!(records[2]["error"]["causes"][0], "fixture domain cause");
        assert_eq!(records[2]["error"]["remediation"], "authorize the fixture");
    }

    #[test]
    fn replay_source_identifier_42_is_data_at_stream_position_zero() {
        let (mut stream, output) = stream(output::contract::Command::Replay);
        let mut selector = OnlyFrame(43);
        render_fixture(
            &mut reader(43),
            Some(&mut selector),
            &mut FakeAuthorizer::default(),
            &mut stream,
        )
        .expect("selected fake replay succeeds");

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["result"]["source_sequence"], 42);
        assert_eq!(records[1]["sequence"], 1);
    }

    #[test]
    fn replay_output_failure_retains_source_frame_context_and_remediation() {
        let mut stream = NdjsonStream::new(Some(output::contract::Command::Replay), FailingWriter);
        let mut selector = OnlyFrame(43);
        let error = render_fixture(
            &mut reader(43),
            Some(&mut selector),
            &mut FakeAuthorizer::default(),
            &mut stream,
        )
        .expect_err("selected replay output must fail");

        assert_eq!(exit_code(&error), 5);
        assert_eq!(error.classification().code, "io.replay");
        assert!(error.to_string().contains("source index 42"));
        assert!(error.to_string().contains("sequence 0"));
        assert_eq!(
            error.classification().remediation,
            Some(
                "inspect the replay timer or output sink and account for frames already transmitted"
            )
        );
        assert!(!stream.is_open());
        assert!(!stream.is_terminal());
    }
}
