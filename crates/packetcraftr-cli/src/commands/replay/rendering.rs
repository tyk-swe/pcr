// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core::error::Kind;

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use packetcraftr::{
    analysis::pcap::{self as capture, Format, Limits, Reader, Writer},
    netio as net, output,
};

use crate::errors::CliError;
use crate::rendering::{
    SourceCaptureWriter, StreamEncoder, emit_aggregate_with_stats, spaced_hex,
    stream_capture_error, write_stdout_line, write_summary_line,
};

type Selector<'a> = Option<&'a mut dyn packetcraftr::replay::Selector>;

pub(super) struct CaptureSettings {
    pub(super) format: Format,
    pub(super) max_interfaces: usize,
}

/// One replay, borrowed for the length of one render: the source, the frame
/// selector, and the three providers a run drives.
///
/// The four renderers take this instead of the same six positional arguments,
/// so every one of them is generic and every one can be driven by fakes.
pub(super) struct Run<'a, R, A, T, C> {
    pub(super) reader: &'a mut Reader<R>,
    pub(super) options: &'a packetcraftr::replay::Options,
    pub(super) selector: Selector<'a>,
    pub(super) authorizer: &'a mut A,
    pub(super) transmitter: &'a mut T,
    pub(super) clock: &'a mut C,
}

impl<R, A, T, C> Run<'_, R, A, T, C>
where
    R: Read,
    A: packetcraftr::replay::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
{
    /// Drives the run, handing each transmitted frame to `record`.
    fn drive(
        self,
        record: impl FnMut(
            packetcraftr::replay::FrameEvidence,
        ) -> Result<(), packetcraftr::replay::Error>,
    ) -> Result<packetcraftr::replay::Summary, CliError> {
        packetcraftr::replay::run_with_selector(
            self.reader,
            self.options,
            self.selector,
            self.authorizer,
            self.transmitter,
            self.clock,
            record,
        )
        .map_err(CliError::classified)
    }
}

pub(super) fn render_text<R, A, T, C>(
    run: Run<'_, R, A, T, C>,
    filtered: bool,
) -> Result<(), CliError>
where
    R: Read,
    A: packetcraftr::replay::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
{
    let summary = run.drive(render_record)?;
    if filtered {
        write_summary_line(format_args!(
            "replayed {} of {} frame(s), {} byte(s), scheduled delay {:?}",
            summary.frames_transmitted,
            summary.frames_read,
            summary.bytes_transmitted,
            summary.scheduled_duration
        ))
    } else {
        write_summary_line(format_args!(
            "replayed {} frame(s), {} byte(s), scheduled delay {:?}",
            summary.frames_transmitted, summary.bytes_transmitted, summary.scheduled_duration
        ))
    }
}

pub(super) fn render_aggregate<R, A, T, C>(
    run: Run<'_, R, A, T, C>,
    requested_interface: net::interface::Id,
) -> Result<(), CliError>
where
    R: Read,
    A: packetcraftr::replay::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
{
    let started = Instant::now();
    let link_mode = run.options.link_mode;
    let mut frames = Vec::new();
    let summary = run.drive(|evidence| {
        frames.push(output_frame(evidence)?);
        Ok(())
    })?;
    let stats = stats(&summary, started.elapsed());
    let result =
        output::replay::Report::from_summary(summary, requested_interface, link_mode, frames);
    emit_aggregate_with_stats(output::contract::Command::Replay, result, Vec::new(), stats)
}

pub(super) fn render_stream<R, A, T, C>(
    run: Run<'_, R, A, T, C>,
    stream: &StreamEncoder,
) -> Result<(), CliError>
where
    R: Read,
    A: packetcraftr::replay::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
{
    let started = Instant::now();
    let interface = run.options.interface.clone();
    let link_mode = run.options.link_mode;
    let summary = run.drive(|evidence| render_stream_record(stream, evidence))?;
    let stats = stats(&summary, started.elapsed());
    let result = output::replay::Report::from_summary(summary, interface, link_mode, Vec::new());
    Ok(stream.complete_with_stats(result, Vec::new(), stats)?)
}

pub(super) fn render_capture<R, A, T, C>(
    run: Run<'_, R, A, T, C>,
    settings: CaptureSettings,
) -> Result<(), CliError>
where
    R: Read,
    A: packetcraftr::replay::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
{
    let stdout = io::stdout();
    let mut writer = capture_writer(
        run.reader,
        stdout.lock(),
        settings.format,
        run.options.limits,
        settings.max_interfaces,
    )?;
    run.drive(|evidence| render_capture_record(&mut writer, evidence))?;
    writer
        .flush()
        .map_err(|source| stream_capture_error("flush capture output failed", source))
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
        "{}: sent {} bytes via {} (index {}, {}) dlt={} {}",
        result.source_index,
        result.bytes_sent,
        result.interface.name,
        result.interface.index,
        result.link_mode,
        result.frame.link_type,
        spaced_hex(result.frame.bytes())
    ))
    .map_err(|source| {
        packetcraftr::replay::Error::output_at_source_index(result.source_index, source.message)
    })
}

fn render_stream_record(
    stream: &StreamEncoder,
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let source_index = evidence.source_index;
    let result = output_frame(evidence)?;
    stream.emit_data(result, Vec::new()).map_err(|error| {
        packetcraftr::replay::Error::output_at_source_index(source_index, error.to_string())
    })
}

fn capture_writer<R: Read, W: Write>(
    reader: &Reader<R>,
    destination: W,
    format: Format,
    limits: packetcraftr::replay::Limits,
    max_interfaces: usize,
) -> Result<SourceCaptureWriter<W>, CliError> {
    let writer = match format {
        Format::Pcap => classic_writer(reader, destination, format, limits)?,
        Format::PcapNg => Writer::pcapng_with_options(
            destination,
            capture::PcapNgOptions {
                endianness: reader.endianness(),
                max_size: limits.max_frame_bytes,
                max_interfaces,
                stream_limits: stream_limits(limits),
            },
        )
        .map_err(|source| stream_capture_error("initialize capture output failed", source))?,
    };
    Ok(SourceCaptureWriter::new(writer))
}

fn classic_writer<R: Read, W: Write>(
    reader: &Reader<R>,
    destination: W,
    format: Format,
    limits: packetcraftr::replay::Limits,
) -> Result<Writer<W>, CliError> {
    if reader.format() != Format::Pcap {
        return Err(CliError::classified(
            capture::Error::MetadataNotRepresentable {
                format,
                field: "pcapng replay evidence",
            },
        ));
    }
    #[expect(
        clippy::indexing_slicing,
        reason = "the format is checked to be classic pcap above, which always exposes its single global interface"
    )]
    let interface = reader.interfaces()[0].clone();
    let snap_length = usize::try_from(interface.snap_len).map_err(|_| {
        CliError::new(
            Kind::Cli,
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
            stream_limits: stream_limits(limits),
        },
    )
    .map_err(|source| stream_capture_error("initialize capture output failed", source))
}

/// The replay budget's aggregate ceilings, in the capture writer's own terms.
const fn stream_limits(limits: packetcraftr::replay::Limits) -> Limits {
    Limits {
        max_frames: limits.max_source_frames,
        max_bytes: limits.max_transmitted_bytes,
    }
}

fn render_capture_record<W: Write>(
    writer: &mut SourceCaptureWriter<W>,
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
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use std::convert::Infallible;
    use std::io::{self, Cursor};
    use std::time::UNIX_EPOCH;

    use packetcraftr::core::error::{Classification, Kind};
    use packetcraftr::core::frame::{Frame, LinkType};

    use super::*;
    use crate::rendering::ndjson_test_support::{assert_contiguous, stream};

    #[derive(Default)]
    struct FakeAuthorizer {
        calls: usize,
        deny_on: Option<usize>,
    }

    impl packetcraftr::replay::Authorizer for FakeAuthorizer {
        fn authorize_operation(
            &mut self,
            _request: packetcraftr::replay::Operation<'_>,
        ) -> Result<(), packetcraftr::BoundaryError> {
            self.calls += 1;
            if self.deny_on == Some(self.calls) {
                return Err(packetcraftr::BoundaryError::new(
                    "fixture policy denied replay",
                    Classification::new(
                        "policy.fixture_replay",
                        Kind::Policy,
                        Some("authorize the fixture"),
                    ),
                    vec!["fixture domain cause".to_owned()],
                ));
            }
            Ok(())
        }

        fn authorize_final_wire(
            &mut self,
            _frame: &Frame,
            _route: &net::route::Plan,
        ) -> Result<(), packetcraftr::BoundaryError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeTransmitter;

    impl packetcraftr::replay::Transmitter for FakeTransmitter {
        fn plan_frame(
            &mut self,
            interface: &net::interface::Id,
            mode: net::link::Mode,
            frame: &Frame,
        ) -> Result<net::route::Materialized, net::Error> {
            let selected_source = "192.0.2.1".parse().expect("fixture source");
            let source_mac = net::link::MacAddress([0x02, 0, 0, 0, 0, 1]);
            let plan = net::route::Plan {
                decision: net::route::Decision {
                    interface: interface.clone(),
                    source_mac: Some(source_mac),
                    selected_source: Some(selected_source),
                    preferred_source: None,
                    next_hop: None,
                    selection_reason: net::route::SelectionReason::InterfaceOnly,
                    destination_scope: net::route::Scope::Link,
                    mtu: 1_500,
                    capability: net::link::Capability::Layer2AndLayer3,
                    link_type: frame.link_type,
                },
                mode,
                lookup_destination: None,
                final_destination: None,
                visited_destinations: Vec::new(),
                packet_source: Some(selected_source),
                neighbor_source: None,
                neighbor_target: None,
                destination_mac: None,
                source_mac: Some(source_mac),
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            };
            Ok(net::route::Materialized {
                plan,
                neighbor_resolution: None,
            })
        }

        fn transmit(
            &mut self,
            route: &net::route::Materialized,
            frame: &Frame,
        ) -> Result<packetcraftr::replay::Transmission, net::Error> {
            Ok(packetcraftr::replay::Transmission {
                interface: route.plan.decision.interface.clone(),
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
        selector: Option<&mut OnlyFrame>,
        authorizer: &mut FakeAuthorizer,
        stream: &StreamEncoder,
    ) -> Result<(), CliError> {
        let options = options();
        let mut transmitter = FakeTransmitter;
        let mut clock = FakeClock;
        render_stream(
            Run {
                reader,
                options: &options,
                selector: selector
                    .map(|selector| selector as &mut dyn packetcraftr::replay::Selector),
                authorizer,
                transmitter: &mut transmitter,
                clock: &mut clock,
            },
            stream,
        )
    }

    #[test]
    fn replay_stream_success_is_contiguous_and_terminal() {
        let (stream, output) = stream(output::contract::Command::Replay);
        render_fixture(
            &mut reader(2),
            None,
            &mut FakeAuthorizer::default(),
            &stream,
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
        let (stream, output) = stream(output::contract::Command::Replay);
        let mut authorizer = FakeAuthorizer {
            calls: 0,
            deny_on: Some(3),
        };
        let error = render_fixture(&mut reader(3), None, &mut authorizer, &stream)
            .expect_err("third fake replay authorization is denied");

        assert_eq!(error.exit_code(), 6);
        assert_eq!(error.classification.code, "policy.fixture_replay");
        assert_eq!(error.causes, ["fixture domain cause"]);
        stream.emit_error(error.output_error()).unwrap();

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records[2]["status"], "error");
        assert_eq!(records[2]["error"]["code"], "policy.fixture_replay");
        assert_eq!(records[2]["error"]["causes"][0], "fixture domain cause");
        assert_eq!(records[2]["error"]["remediation"], "authorize the fixture");
    }

    #[test]
    fn replay_source_identifier_42_is_data_at_stream_position_zero() {
        let (stream, output) = stream(output::contract::Command::Replay);
        let mut selector = OnlyFrame(43);
        render_fixture(
            &mut reader(43),
            Some(&mut selector),
            &mut FakeAuthorizer::default(),
            &stream,
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
        let stream = StreamEncoder::new(output::contract::Command::Replay, FailingWriter);
        let mut selector = OnlyFrame(43);
        let error = render_fixture(
            &mut reader(43),
            Some(&mut selector),
            &mut FakeAuthorizer::default(),
            &stream,
        )
        .expect_err("selected replay output must fail");

        assert_eq!(error.exit_code(), 5);
        assert_eq!(error.classification.code, "io.replay");
        assert!(error.message.contains("source index 42"));
        assert!(error.message.contains("sequence 0"));
        assert_eq!(
            error.classification.remediation,
            Some(
                "inspect the replay timer or output sink and account for frames already transmitted"
            )
        );
        assert!(!stream.is_open());
        assert!(!stream.is_terminal());
    }
}
