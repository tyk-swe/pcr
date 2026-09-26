// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::files::Files;
use crate::output::{
    self,
    contract::{CaptureFormat, Command},
};
use crate::{
    command_options::Compression,
    errors::CliError,
    filtering::{FrameDecoder, FrameSelector},
    rendering::{
        StreamEncoder, captured_frame_text, document_spelling, emit_aggregate_with_stats,
        render_diagnostics_stderr, render_diagnostics_text, write_plain_line, write_stdout_line,
        write_summary_line,
    },
};
use packetcraftr::{
    Stats,
    capture::{self, Control, Event},
};
use packetcraftr_core::{
    self as core,
    analysis::pcap::{self, compression},
    decode::DecodedPacket,
    error::{BoundaryError, Classified},
    frame::Frame,
    registry::Registry,
};
use packetcraftr_netio::capture::{Provider, group};
use std::cell::RefCell;
use std::io;
use std::sync::Arc;

/// Shared per-frame decoding for `--filter`, `--dissect`, and `--field`.
/// Selection decodes a kept frame once and parks it so emission republishes
/// the same dissection; decoded state never outlives one frame.
pub(super) struct Decoding {
    frames: FrameDecoder,
    parked: RefCell<Option<(u64, DecodedPacket)>>,
}

impl Decoding {
    /// Builds the shared decoding state, or `None` when neither `--dissect`
    /// nor `--field` asked for decoded output. `parked` starts empty.
    pub(super) fn prepare(
        dissect: bool,
        projector: bool,
        filter: Option<&str>,
        registry: &Arc<Registry>,
        snap_length: usize,
    ) -> Result<Option<Self>, CliError> {
        if !dissect && !projector {
            return Ok(None);
        }
        Ok(Some(Self {
            frames: FrameDecoder::compile(registry, filter, snap_length)?,
            parked: RefCell::new(None),
        }))
    }

    /// The filter half of frame selection, run by the capture admission
    /// callback; a kept frame's dissection is parked for the emit callback.
    pub(super) fn select(&self, source_frame: u64, frame: &Frame) -> Result<bool, CliError> {
        let Some(decoded) = self.frames.decode_selected(source_frame, frame)? else {
            return Ok(false);
        };
        self.parked.replace(Some((source_frame, decoded)));
        Ok(true)
    }

    /// Reuses the dissection `select` parked for this frame, decoding only
    /// when no selection ran for it (the no-filter case).
    pub(super) fn take_or_decode(
        &self,
        source_frame: u64,
        frame: &Frame,
    ) -> Result<DecodedPacket, CliError> {
        if let Some((number, decoded)) = self.parked.take()
            && number == source_frame
        {
            return Ok(decoded);
        }
        self.frames.decode(frame)
    }
}

pub(super) struct Rendering<'a> {
    pub(super) format: CaptureFormat,
    pub(super) compression: Compression,
    pub(super) selector: Option<FrameSelector>,
    pub(super) decoding: Option<Decoding>,
    pub(super) projector: Option<super::super::projection::Projector>,
    pub(super) files: Option<Files>,
    pub(super) stream: &'a StreamEncoder,
}
/// Provider composition is injected so normal capture, rotation, and mixed
/// interfaces all exercise the same workflow and finalization path.
pub(super) fn run<P: Provider>(
    provider: &P,
    request: &group::Request,
    options: capture::Options,
    mut rendering: Rendering<'_>,
) -> Result<(), CliError> {
    let limits = pcap::Limits {
        max_frames: options.budget.max_frames(),
        max_bytes: options.budget.max_bytes(),
    };
    let mut writer: Option<pcap::Writer<compression::Output<io::Stdout>>> = None;
    let format = rendering.format;
    let result = capture::run(
        provider,
        request,
        options,
        |number, frame| {
            if let Some(decoding) = &rendering.decoding {
                return decoding
                    .select(number, frame)
                    .map_err(CliError::into_boundary_error);
            }
            rendering
                .selector
                .as_ref()
                .map(|selector| selector.keep(number, frame))
                .transpose()
                .map_err(CliError::into_boundary_error)
                .map(|keep| keep.unwrap_or(true))
        },
        |event| match event {
            Event::Started { sources } => {
                if let Some(files) = &mut rendering.files {
                    files
                        .initialize(sources)
                        .map_err(BoundaryError::from_error)?;
                } else if matches!(format, CaptureFormat::Pcap | CaptureFormat::PcapNg) {
                    let destination =
                        compression::Output::new(io::stdout(), rendering.compression.format())
                            .map_err(BoundaryError::from_error)?;
                    writer = Some(
                        super::writer::initialize(
                            destination,
                            if format == CaptureFormat::Pcap {
                                pcap::Format::Pcap
                            } else {
                                pcap::Format::PcapNg
                            },
                            &sources,
                            limits,
                        )
                        .map_err(BoundaryError::from_error)?,
                    );
                }
                Ok(Control::Continue)
            }
            Event::Frame {
                source_frame,
                elapsed,
                frame,
                ..
            } => {
                let control = if let Some(files) = &mut rendering.files {
                    files
                        .write(&frame, source_frame, elapsed)
                        .map_err(BoundaryError::from_error)?
                } else {
                    Control::Continue
                };
                if control == Control::StopBefore {
                    return Ok(control);
                }
                let emitted = emit_frame(
                    rendering.decoding.as_ref(),
                    rendering.projector.as_mut(),
                    rendering.stream,
                    format,
                    &mut writer,
                    source_frame,
                    frame,
                );
                emitted.map_err(CliError::into_boundary_error)?;
                Ok(control)
            }
        },
    );
    // Finalize every initialized destination even when capture or a consumer
    // failed, retaining whatever complete records reached the writer.
    let file_finish = rendering
        .files
        .as_mut()
        .map(Files::finish)
        .transpose()
        .map_err(CliError::classified);
    let binary_finish = writer
        .map(|writer| writer.into_inner().finish())
        .transpose()
        .map_err(CliError::classified);
    let files = rendering.files.as_ref().map(Files::report);
    let (report, mut error) = match result {
        Ok(report) => (report, None),
        Err(error) => {
            let cli = CliError::from_classification(
                error.classification(),
                error.to_string(),
                error.causes(),
            )
            .with_context(error.context());
            (*error.report, Some(cli))
        }
    };
    for failure in [file_finish.err(), binary_finish.err()]
        .into_iter()
        .flatten()
    {
        error = Some(match error.take() {
            Some(primary) => primary.with_secondary("output finalization", failure),
            None => failure,
        });
    }

    let summary = output::capture::Summary::from_capture(&report, files);
    if let Some(error) = error {
        return Err(error.with_capture(output::capture::Snapshot {
            summary,
            stats: report.stats,
        }));
    }
    // A projection that never matched a frame still owes its text header; the
    // NDJSON terminal is the capture summary, never a second complete record.
    if format == CaptureFormat::Text
        && let Some(projector) = rendering.projector.take()
    {
        projector
            .finish(
                report.frames_delivered,
                report.stats.bytes,
                rendering.stream,
            )
            .map_err(|error| {
                error.with_capture(output::capture::Snapshot {
                    summary: summary.clone(),
                    stats: report.stats.clone(),
                })
            })?;
    }
    render_complete(
        format,
        &summary,
        &report.stats,
        report.diagnostics,
        rendering.stream,
    )
    .map_err(|error| {
        error.with_capture(output::capture::Snapshot {
            summary,
            stats: report.stats,
        })
    })
}

/// Publishes one matched frame. Decoded output reuses the dissection the
/// admission callback parked, projections stream as bounded `fields` records,
/// and every sink error propagates so capture cleanup still runs.
fn emit_frame(
    decoding: Option<&Decoding>,
    projector: Option<&mut super::super::projection::Projector>,
    stream: &StreamEncoder,
    format: CaptureFormat,
    writer: &mut Option<pcap::Writer<compression::Output<io::Stdout>>>,
    source_frame: u64,
    frame: Frame,
) -> Result<(), CliError> {
    if let Some(decoding) = decoding {
        let decoded = decoding.take_or_decode(source_frame, &frame)?;
        if let Some(projector) = projector {
            let values = projector
                .projection
                .values(
                    &core::filter::Context {
                        decoded: &decoded,
                        derived: &[],
                        number: source_frame,
                        tcp_stream: None,
                        udp_stream: None,
                    },
                    projector.remaining(),
                )
                .map_err(CliError::classified)?;
            return projector.emit(source_frame, values, stream);
        }
        return match format {
            CaptureFormat::Text => {
                // Only the text rendering needs a stack here; the NDJSON event
                // builds its own inside `try_from_decoded`.
                let stack = output::frame::Stack::from_decoded(&decoded);
                let frame =
                    output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
                let source_frame = source_frame.try_into().map_err(CliError::classified)?;
                super::super::read::rendering::render_frame_text(source_frame, &frame, Some(&stack))
            }
            CaptureFormat::Ndjson => {
                output::capture::Event::try_from_decoded(source_frame, frame, &decoded)
                    .map_err(CliError::classified)
                    .and_then(|event| stream.emit_data(event, Vec::new()).map_err(Into::into))
            }
            CaptureFormat::Json
            | CaptureFormat::Hex
            | CaptureFormat::Pcap
            | CaptureFormat::PcapNg => Err(CliError::new(
                packetcraftr_core::error::Kind::Internal,
                "decoded output requires text or NDJSON",
            )),
        };
    }
    match format {
        CaptureFormat::Text => output::frame::Captured::try_from_frame(frame)
            .map_err(CliError::classified)
            .and_then(|frame| {
                write_stdout_line(format_args!(
                    "{source_frame}: {}",
                    captured_frame_text(&frame)
                ))
            }),
        CaptureFormat::Hex => output::frame::Captured::try_from_frame(frame)
            .map_err(CliError::classified)
            .and_then(|frame| write_plain_line(format_args!("{}", frame.bytes_hex()))),
        CaptureFormat::Ndjson => output::capture::Event::try_from_frame(source_frame, frame)
            .map_err(CliError::classified)
            .and_then(|event| stream.emit_data(event, Vec::new()).map_err(Into::into)),
        CaptureFormat::Json => Ok(()),
        CaptureFormat::Pcap | CaptureFormat::PcapNg => writer
            .as_mut()
            .expect("writer initialized before frames")
            .write_frame(&frame)
            .map_err(CliError::classified),
    }
}
fn render_complete(
    format: CaptureFormat,
    summary: &output::capture::Summary,
    stats: &Stats,
    diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    match format {
        CaptureFormat::Json => {
            emit_aggregate_with_stats(Command::Capture, summary, diagnostics, stats.clone())
        }
        CaptureFormat::Ndjson => stream
            .complete_with_stats(summary, diagnostics, stats.clone())
            .map_err(Into::into),
        CaptureFormat::Text => {
            write_summary_line(format_args!(
                "captured {} frames ({} emitted), {} bytes across {} interfaces; stopped for {}",
                stats.packets_attempted,
                stats.packets_completed,
                stats.bytes,
                summary.sources.len(),
                document_spelling(&summary.stop_reason)
            ))?;
            for source in &summary.sources {
                if let Some(settings) = &source.capture_settings {
                    write_plain_line(format_args!(
                        "  source {} ({}): buffer_size {} timestamp_source {} timestamp_precision {}",
                        source.capture_id,
                        source.native_interface.name,
                        realized_text(&settings.buffer_size),
                        realized_text(&settings.timestamp_source),
                        realized_text(&settings.timestamp_precision),
                    ))?;
                }
            }
            if let Some(files) = &summary.files {
                for file in &files.files {
                    write_plain_line(format_args!(
                        "  {}: {} frames, {} capture bytes, finalized={}",
                        file.path, file.frames, file.capture_bytes, file.finalized
                    ))?;
                }
                write_plain_line(format_args!(
                    "  retention={}, retired files={}, retired frames={}",
                    document_spelling(&files.retention),
                    files.discarded_files,
                    files.discarded_frames
                ))?;
            }
            render_diagnostics_text(&diagnostics)
        }
        _ => render_diagnostics_stderr(&diagnostics),
    }
}

/// `requested/applied/effective` in one parenthesized triplet; `default` marks
/// an unset request, `-` a setting never applied, and `unknown` a value the
/// backend cannot confirm.
fn realized_text<T: std::fmt::Display>(
    realized: &packetcraftr_netio::capture::Realized<T>,
) -> String {
    fn field<T: std::fmt::Display>(value: &Option<T>, none: &str) -> String {
        value
            .as_ref()
            .map_or_else(|| none.to_owned(), ToString::to_string)
    }
    format!(
        "(requested={} applied={} effective={})",
        field(&realized.requested, "default"),
        field(&realized.applied, "-"),
        field(&realized.effective, "unknown"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::stream;
    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_netio::{self as net, capture as native, interface::Id};
    use std::{
        collections::VecDeque,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, UNIX_EPOCH},
    };
    struct Session {
        metadata: native::Metadata,
        frames: VecDeque<native::Captured>,
        stopped: Arc<AtomicUsize>,
        failed: bool,
    }
    impl native::Session for Session {
        fn metadata(&self) -> &native::Metadata {
            &self.metadata
        }
        fn wait_ready(&mut self, _: Duration) -> Result<(), net::Error> {
            Ok(())
        }
        fn next_captured_frame(
            &mut self,
            _: Duration,
        ) -> Result<Option<native::Captured>, net::Error> {
            if let Some(frame) = self.frames.pop_front() {
                return Ok(Some(frame));
            }
            if self.failed {
                return Err(net::Error::Capture {
                    message: "fixture receive failure".to_owned(),
                    source: None,
                });
            }
            Ok(None)
        }
        fn shutdown(&mut self) -> Result<(), net::Error> {
            self.stopped.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn statistics(&self) -> native::Statistics {
            native::Statistics {
                received_frames: 1,
                received_bytes: 4,
                ..Default::default()
            }
        }
    }
    struct Provider {
        captures: Mutex<VecDeque<Session>>,
    }
    impl native::Provider for Provider {
        type Capture = Session;
        fn arm_capture(&self, _: &native::Request) -> Result<Session, net::Error> {
            Ok(self.captures.lock().unwrap().pop_front().unwrap())
        }
    }
    fn fixture(fail: bool) -> (Provider, group::Request, Vec<Arc<AtomicUsize>>) {
        let interfaces: Vec<_> = (0..2)
            .map(|index| Id {
                index: index + 7,
                name: format!("fixture{index}"),
            })
            .collect();
        let mut captures = VecDeque::new();
        let mut stopped = Vec::new();
        for (index, interface) in interfaces.iter().enumerate() {
            let counter = Arc::new(AtomicUsize::new(0));
            stopped.push(counter.clone());
            let link_type = if index == 0 {
                LinkType::RAW
            } else {
                LinkType::ETHERNET
            };
            let frame = Frame::new(UNIX_EPOCH, link_type, vec![index as u8; 4]).unwrap();
            captures.push_back(Session {
                metadata: native::Metadata {
                    interface: interface.clone(),
                    link_type,
                    snap_length: 64,
                    native: Default::default(),
                },
                frames: VecDeque::from([native::Captured::without_ingress_time(frame)]),
                stopped: counter,
                failed: fail && index == 0,
            });
        }
        (
            Provider {
                captures: Mutex::new(captures),
            },
            group::Request {
                interfaces,
                limits: native::Limits {
                    max_frames: 8,
                    max_bytes: 128,
                    snap_length: 64,
                    ..Default::default()
                },
                filter: None,
                promiscuous: false,
                native: Default::default(),
            },
            stopped,
        )
    }
    fn options(count: u64) -> capture::Options {
        capture::Options {
            window: Duration::from_secs(1),
            budget: packetcraftr::policy::CaptureBudget::new(&packetcraftr::policy::Policy {
                max_packets_per_operation: count,
                max_bytes_per_operation: 1024,
                ..Default::default()
            }),
            cancellation: None,
        }
    }
    #[test]
    fn mixed_interfaces_share_output_ids_and_completion_statistics() {
        let (provider, request, stopped) = fixture(false);
        let (publisher, buffer) = stream(Command::Capture);
        run(
            &provider,
            &request,
            options(2),
            Rendering {
                format: CaptureFormat::Ndjson,
                compression: Compression::None,
                selector: None,
                decoding: None,
                projector: None,
                files: None,
                stream: &publisher,
            },
        )
        .unwrap();
        let records = buffer.records();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["result"]["frame"]["interface"], 0);
        assert_eq!(records[1]["result"]["frame"]["interface"], 1);
        assert_eq!(records[2]["result"]["sources"].as_array().unwrap().len(), 2);
        assert_eq!(records[2]["stats"]["packets_attempted"], 2);
        assert!(
            stopped
                .iter()
                .all(|count| count.load(Ordering::SeqCst) == 1)
        );
        let validator = crate::test_support::schema_validator();
        for record in records {
            assert!(validator.is_valid(&record), "{record}");
        }
    }
    #[test]
    fn runtime_failure_finalizes_saved_capture_and_retains_partial_evidence() {
        let (provider, request, stopped) = fixture(true);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("partial.pcapng.gz");
        let files = Files::new(
            super::super::files::Options {
                path: path.clone(),
                compression: Compression::Gzip,
                rotate_bytes: None,
                rotate_after: None,
                max_files: 1,
                retention: output::capture::Retention::Stop,
            },
            pcap::Limits {
                max_frames: 10,
                max_bytes: 1024,
            },
        )
        .unwrap();
        let (publisher, buffer) = stream(Command::Capture);
        let error = run(
            &provider,
            &request,
            options(10),
            Rendering {
                format: CaptureFormat::Ndjson,
                compression: Compression::None,
                selector: None,
                decoding: None,
                projector: None,
                files: Some(files),
                stream: &publisher,
            },
        )
        .unwrap_err();
        assert!(error.message.contains("fixture receive failure"));
        assert!(
            stopped
                .iter()
                .all(|count| count.load(Ordering::SeqCst) == 1)
        );
        let value = serde_json::to_value(error.output_error()).unwrap();
        assert_eq!(
            value["capture"]["summary"]["files"]["files"][0]["finalized"],
            true
        );
        assert_eq!(value["capture"]["summary"]["files"]["frames_written"], 2);
        assert_eq!(buffer.records().len(), 2);
        let input = compression::Input::new(std::fs::File::open(path).unwrap(), Default::default())
            .unwrap();
        let mut reader = pcap::Reader::new(input).unwrap();
        assert_eq!(reader.next_frame().unwrap().unwrap().interface, Some(0));
        assert_eq!(reader.next_frame().unwrap().unwrap().interface, Some(1));
        assert!(reader.next_frame().unwrap().is_none());
    }

    fn single_session(
        link_type: LinkType,
        frames: Vec<Vec<u8>>,
    ) -> (Provider, group::Request, Vec<Arc<AtomicUsize>>) {
        let interface = Id {
            index: 7,
            name: "fixture0".to_owned(),
        };
        let counter = Arc::new(AtomicUsize::new(0));
        let session = Session {
            metadata: native::Metadata {
                interface: interface.clone(),
                link_type,
                snap_length: 256,
                native: Default::default(),
            },
            frames: frames
                .into_iter()
                .map(|bytes| {
                    native::Captured::without_ingress_time(
                        Frame::new(UNIX_EPOCH, link_type, bytes).unwrap(),
                    )
                })
                .collect(),
            stopped: counter.clone(),
            failed: false,
        };
        (
            Provider {
                captures: Mutex::new(VecDeque::from([session])),
            },
            group::Request {
                interfaces: vec![interface],
                limits: native::Limits {
                    max_frames: 8,
                    max_bytes: 4096,
                    snap_length: 256,
                    ..Default::default()
                },
                filter: None,
                promiscuous: false,
                native: Default::default(),
            },
            vec![counter],
        )
    }

    /// Ethernet/IPv4/UDP with a verified header checksum and four payload bytes.
    fn ipv4_udp_frame() -> Vec<u8> {
        vec![
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0xf6, 0xc8, 0xc0, 0x00,
            0x02, 0x01, 0xc0, 0x00, 0x02, 0x02, 0xd4, 0x31, 0x30, 0x39, 0x00, 0x0c, 0x00, 0x00,
            0xde, 0xad, 0xbe, 0xef,
        ]
    }

    fn registry() -> Arc<packetcraftr_core::registry::Registry> {
        packetcraftr_core::protocol::builtin::registry()
    }

    fn dissecting() -> Option<Decoding> {
        Decoding::prepare(true, false, None, &registry(), 256).unwrap()
    }

    #[test]
    fn dissected_frames_retain_bytes_metadata_and_diagnostics() {
        let mut bytes = ipv4_udp_frame();
        let truncated: Vec<u8> = bytes[..26].to_vec();
        // An unknown ethertype keeps a valid Ethernet header over raw payload.
        bytes[12] = 0x88;
        bytes[13] = 0xb5;
        let (provider, request, stopped) =
            single_session(LinkType::ETHERNET, vec![ipv4_udp_frame(), truncated, bytes]);
        let (publisher, buffer) = stream(Command::Capture);
        run(
            &provider,
            &request,
            options(3),
            Rendering {
                format: CaptureFormat::Ndjson,
                compression: Compression::None,
                selector: None,
                decoding: dissecting(),
                projector: None,
                files: None,
                stream: &publisher,
            },
        )
        .unwrap();
        let records = buffer.records();
        assert_eq!(records.len(), 4);
        let validator = crate::test_support::schema_validator();
        for record in &records {
            assert!(validator.is_valid(record), "{record}");
        }
        let valid = &records[0]["result"];
        let layers: Vec<_> = valid["decoded"]["packet"]["layers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|layer| layer["protocol"].as_str().unwrap())
            .collect();
        assert_eq!(layers, ["ethernet", "ipv4", "udp", "raw"]);
        // Captured bytes and interface metadata survive beside the dissection.
        assert_eq!(
            valid["frame"]["bytes_hex"].as_str().unwrap(),
            "aabbccddeeff112233445566080045000020000100004011f6c8c0000201c0000202d4313039000c0000deadbeef"
        );
        assert_eq!(valid["frame"]["interface"], 0);
        assert!(
            valid["decoded"]["diagnostics"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        // Truncation surfaces as decode diagnostics, not a dropped frame.
        let truncated = &records[1]["result"];
        assert!(
            !truncated["decoded"]["diagnostics"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(truncated["frame"]["captured_length"], 26);
        // Unknown protocol payloads still dissect to their known layers.
        let unknown = &records[2]["result"];
        let layers: Vec<_> = unknown["decoded"]["packet"]["layers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|layer| layer["protocol"].as_str().unwrap())
            .collect();
        assert_eq!(layers.first(), Some(&"ethernet"));
        assert!(
            stopped
                .iter()
                .all(|count| count.load(Ordering::SeqCst) == 1)
        );
    }

    #[test]
    fn projection_streams_bounded_fields_records() {
        let (provider, request, stopped) =
            single_session(LinkType::ETHERNET, vec![ipv4_udp_frame()]);
        let (publisher, buffer) = stream(Command::Capture);
        let projector = super::super::super::projection::Projector::prepare(
            &["frame.len".to_owned(), "ipv4.destination".to_owned()],
            4096,
            &registry(),
            Command::Capture,
            CaptureFormat::Ndjson.as_format(),
        )
        .unwrap();
        run(
            &provider,
            &request,
            options(1),
            Rendering {
                format: CaptureFormat::Ndjson,
                compression: Compression::None,
                selector: None,
                decoding: Decoding::prepare(false, true, None, &registry(), 256).unwrap(),
                projector,
                files: None,
                stream: &publisher,
            },
        )
        .unwrap();
        let records = buffer.records();
        assert_eq!(records.len(), 2);
        let row = &records[0];
        assert_eq!(row["event"], "fields");
        assert_eq!(row["result"]["source_frame"], 1);
        assert_eq!(
            row["result"]["columns"],
            serde_json::json!(["frame.len", "ipv4.destination"])
        );
        assert_eq!(
            row["result"]["values"],
            serde_json::json!([46, "192.0.2.2"])
        );
        assert_eq!(records[1]["event"], "complete");
        assert_eq!(records[1]["result"]["frames_delivered"], 1);
        let validator = crate::test_support::schema_validator();
        for record in &records {
            assert!(validator.is_valid(record), "{record}");
        }
        assert!(
            stopped
                .iter()
                .all(|count| count.load(Ordering::SeqCst) == 1)
        );
    }

    #[test]
    fn projection_exhaustion_stops_capture_and_retains_evidence() {
        let (provider, request, stopped) =
            single_session(LinkType::ETHERNET, vec![ipv4_udp_frame(), ipv4_udp_frame()]);
        let (publisher, buffer) = stream(Command::Capture);
        let projector = super::super::super::projection::Projector::prepare(
            &["frame.len".to_owned(), "ipv4.destination".to_owned()],
            16,
            &registry(),
            Command::Capture,
            CaptureFormat::Ndjson.as_format(),
        )
        .unwrap();
        let error = run(
            &provider,
            &request,
            options(2),
            Rendering {
                format: CaptureFormat::Ndjson,
                compression: Compression::None,
                selector: None,
                decoding: Decoding::prepare(false, true, None, &registry(), 256).unwrap(),
                projector,
                files: None,
                stream: &publisher,
            },
        )
        .unwrap_err();
        assert_eq!(error.classification.code, "policy.projection_limit");
        let value = serde_json::to_value(error.output_error()).unwrap();
        assert_eq!(value["capture"]["summary"]["frames_delivered"], 1);
        assert!(
            stopped
                .iter()
                .all(|count| count.load(Ordering::SeqCst) == 1)
        );
        drop(buffer);
    }

    #[test]
    fn sink_failure_stops_capture_and_shuts_sources_down() {
        struct Broken;
        impl io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("fixture sink failure"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (provider, request, stopped) =
            single_session(LinkType::ETHERNET, vec![ipv4_udp_frame()]);
        let publisher = StreamEncoder::new(Command::Capture, Broken);
        let error = run(
            &provider,
            &request,
            options(1),
            Rendering {
                format: CaptureFormat::Ndjson,
                compression: Compression::None,
                selector: None,
                decoding: dissecting(),
                projector: None,
                files: None,
                stream: &publisher,
            },
        )
        .unwrap_err();
        assert_eq!(error.classification.code, "io.stdout");
        let value = serde_json::to_value(error.output_error()).unwrap();
        assert_eq!(value["capture"]["summary"]["frames_delivered"], 1);
        assert!(
            stopped
                .iter()
                .all(|count| count.load(Ordering::SeqCst) == 1)
        );
    }

    #[test]
    fn filtered_decoding_parks_one_dissection_per_emission() {
        let (provider, request, stopped) =
            single_session(LinkType::ETHERNET, vec![ipv4_udp_frame(), vec![0u8; 8]]);
        let (publisher, buffer) = stream(Command::Capture);
        let decoding = Decoding::prepare(
            true,
            false,
            Some("ipv4.destination == 192.0.2.2"),
            &registry(),
            256,
        )
        .unwrap();
        run(
            &provider,
            &request,
            options(2),
            Rendering {
                format: CaptureFormat::Ndjson,
                compression: Compression::None,
                selector: None,
                decoding,
                projector: None,
                files: None,
                stream: &publisher,
            },
        )
        .unwrap();
        let records = buffer.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["result"]["source_frame"], 1);
        assert_eq!(
            records[0]["result"]["decoded"]["packet"]["layers"][1]["protocol"],
            "ipv4"
        );
        assert_eq!(records[1]["result"]["sources"][0]["matched_frames"], 1);
        assert!(
            stopped
                .iter()
                .all(|count| count.load(Ordering::SeqCst) == 1)
        );
    }
}
