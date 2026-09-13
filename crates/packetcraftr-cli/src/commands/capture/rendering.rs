// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::files::Files;
use crate::{
    command_options::Compression,
    errors::CliError,
    filtering::FrameSelector,
    rendering::{
        StreamEncoder, captured_frame_text, emit_aggregate_with_stats, render_diagnostics_stderr,
        render_diagnostics_text, write_plain_line, write_stdout_line, write_summary_line,
    },
};
use packetcraftr::{
    Stats,
    capture::{self, Control, Event},
};
use packetcraftr_cli::output::{
    self,
    contract::{Command, Format},
};
use packetcraftr_core::{
    analysis::pcap::{self, compression},
    error::{BoundaryError, Classified},
};
use packetcraftr_netio::capture::{Provider, group};
use std::io;

pub(super) struct Rendering<'a> {
    pub(super) format: Format,
    pub(super) compression: Compression,
    pub(super) selector: Option<FrameSelector>,
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
                } else if matches!(format, Format::Pcap | Format::PcapNg) {
                    let destination =
                        compression::Output::new(io::stdout(), rendering.compression.format())
                            .map_err(BoundaryError::from_error)?;
                    writer = Some(
                        super::writer::initialize(
                            destination,
                            if format == Format::Pcap {
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
                let emitted = match format {
                    Format::Text => output::frame::Captured::try_from_frame(frame)
                        .map_err(CliError::classified)
                        .and_then(|frame| {
                            write_stdout_line(format_args!(
                                "{source_frame}: {}",
                                captured_frame_text(&frame)
                            ))
                        }),
                    Format::Hex => output::frame::Captured::try_from_frame(frame)
                        .map_err(CliError::classified)
                        .and_then(|frame| write_plain_line(format_args!("{}", frame.bytes_hex()))),
                    Format::Ndjson => output::capture::Event::try_from_frame(source_frame, frame)
                        .map_err(CliError::classified)
                        .and_then(|event| {
                            rendering
                                .stream
                                .emit_data(event, Vec::new())
                                .map_err(Into::into)
                        }),
                    Format::Json => Ok(()),
                    Format::Pcap | Format::PcapNg => writer
                        .as_mut()
                        .expect("writer initialized before frames")
                        .write_frame(&frame)
                        .map_err(CliError::classified),
                    _ => unreachable!("format checked before activation"),
                };
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
fn render_complete(
    format: Format,
    summary: &output::capture::Summary,
    stats: &Stats,
    diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    match format {
        Format::Json => {
            emit_aggregate_with_stats(Command::Capture, summary, diagnostics, stats.clone())
        }
        Format::Ndjson => stream
            .complete_with_stats(summary, diagnostics, stats.clone())
            .map_err(Into::into),
        Format::Text => {
            write_summary_line(format_args!(
                "captured {} frames ({} emitted), {} bytes across {} interfaces; stopped for {:?}",
                stats.packets_attempted,
                stats.packets_completed,
                stats.bytes,
                summary.sources.len(),
                summary.stop_reason
            ))?;
            if let Some(files) = &summary.files {
                for file in &files.files {
                    write_plain_line(format_args!(
                        "  {}: {} frames, {} capture bytes, finalized={}",
                        file.path, file.frames, file.capture_bytes, file.finalized
                    ))?;
                }
                write_plain_line(format_args!(
                    "  retention={:?}, retired files={}, retired frames={}",
                    files.retention, files.discarded_files, files.discarded_frames
                ))?;
            }
            render_diagnostics_text(&diagnostics)
        }
        _ => render_diagnostics_stderr(&diagnostics),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendering::ndjson_test_support::stream;
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
                format: Format::Ndjson,
                compression: Compression::None,
                selector: None,
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
                format: Format::Ndjson,
                compression: Compression::None,
                selector: None,
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
}
