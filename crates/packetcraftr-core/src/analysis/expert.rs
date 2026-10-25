// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-frame protocol health findings computed over the analysis pipeline.

use std::collections::{BTreeMap, HashMap};

use crate::diagnostic::Severity;
use crate::protocol::transport::Tcp;

use crate::analysis::pipeline::{FrameRecord, Summary as RunSummary};
use crate::analysis::reassembly::tcp::{Event as TcpEvent, ScopedFlowKey};
use crate::analysis::session::{self, CollectorNeeds};
use crate::analysis::{StreamRef, StreamTransport};
use crate::error::BoundaryError;

use tcp::DirectionState;

mod finding;
mod generation;
mod observation;
mod selector;
mod tcp;

pub use selector::Selector;

const fn tcp_stream_ref(index: u64) -> StreamRef {
    StreamRef {
        transport: StreamTransport::Tcp,
        index,
    }
}

const fn udp_stream_ref(index: u64) -> StreamRef {
    StreamRef {
        transport: StreamTransport::Udp,
        index,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    /// 1-based capture frame number that revealed the condition.
    pub number: u64,
    pub stream: Option<StreamRef>,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub clock: crate::analysis::ClockReport,
    pub findings: u64,
    pub errors: u64,
    pub warnings: u64,
    pub notes: u64,
    pub codes: BTreeMap<&'static str, u64>,
}

impl Summary {
    /// Tallies one finding into the totals, per-severity counters and per-code counts.
    // u64 finding counters cannot reach u64::MAX from a bounded frame count
    pub fn record(&mut self, finding: &Finding) {
        self.findings += 1;
        match finding.severity {
            Severity::Error => self.errors += 1,
            Severity::Warning => self.warnings += 1,
            Severity::Info => self.notes += 1,
        }
        *self.codes.entry(finding.code).or_default() += 1;
    }
}

#[derive(Debug, Default)]
pub struct Collector {
    flows: HashMap<ScopedFlowKey, DirectionState>,
    streams: HashMap<ScopedFlowKey, u64>,
    summary: Summary,
}

impl Collector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Vec<Finding> {
        let mut findings = finding::from_capture_evidence(record);
        findings.extend(finding::from_diagnostics(record));
        let tcp = record
            .tcp
            .and_then(|tcp| tcp.conversation.map(|conversation| (conversation, tcp)));
        // Handshake verdicts read the flow as it stood before this frame's own evictions.
        let prior =
            tcp.map(|(conversation, _)| tcp::Prior::capture(&self.flows, conversation.flow));
        self.reconcile_tcp_evictions(record.tcp_events);
        if let (Some((conversation, tcp)), Some(prior)) = (tcp, prior) {
            self.observe_tcp(record, conversation, tcp, prior, &mut findings);
        }

        for finding in &findings {
            self.summary.record(finding);
        }
        findings
    }

    pub fn finish(self, summary: &RunSummary) -> (Vec<Finding>, Summary) {
        let mut findings = Vec::new();
        let summary = self
            .finalize(summary, &mut || Ok(()), &mut |finding| {
                findings.push(finding);
                Ok(())
            })
            .expect("uncontrolled collection cannot fail");
        (findings, summary)
    }

    fn finalize(
        mut self,
        summary: &RunSummary,
        check: &mut dyn FnMut() -> Result<(), BoundaryError>,
        emit: &mut dyn FnMut(Finding) -> Result<(), BoundaryError>,
    ) -> Result<Summary, BoundaryError> {
        check()?;
        self.summary.clock = summary.clock.clone();
        tcp::finish(
            &self.flows,
            &self.streams,
            &summary.trailing_tcp_events,
            summary.frames_read,
            check,
            &mut |finding| {
                self.summary.record(&finding);
                emit(finding)
            },
        )?;
        check()?;
        Ok(self.summary)
    }
}

impl session::Collector for Collector {
    type Event = Finding;
    type Summary = Summary;

    fn needs(&self) -> CollectorNeeds {
        CollectorNeeds {
            tcp_stream: true,
            udp_stream: true,
            ip_reassembly: true,
            tcp_events: true,
            ..CollectorNeeds::default()
        }
    }

    fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Finding>, BoundaryError> {
        Ok(Self::observe(self, record))
    }

    fn finish(self, run: &RunSummary) -> Result<(Vec<Finding>, Summary), BoundaryError> {
        Ok(Self::finish(self, run))
    }

    fn finish_controlled(
        self,
        run: &RunSummary,
        deadline: &crate::budget::Deadline,
        event_sink: &mut dyn FnMut(Finding) -> Result<(), BoundaryError>,
    ) -> Result<Summary, BoundaryError> {
        self.finalize(run, &mut || session::check(deadline), &mut |finding| {
            session::deliver(deadline, std::iter::once(finding), event_sink)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::{self, Plan, Session},
        budget::Deadline,
        build::Builder,
        capture_file::{Format, Reader, Writer},
        frame::{Frame, Lengths, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{builtin, network::Ipv4, transport::Udp},
        registry::Registry,
    };
    use std::{
        io::Cursor,
        net::Ipv4Addr,
        sync::Arc,
        time::{Duration, Instant, UNIX_EPOCH},
    };

    #[derive(Clone, Copy)]
    enum Lifecycle {
        Session,
        Direct,
    }

    fn registry() -> Arc<Registry> {
        Arc::new(
            builtin::registry_with(|builder| {
                for protocol in ["tcp", "udp"] {
                    for port in [40000_u64, 40001, 40002] {
                        builder.bind(protocol, port, "raw", i32::MAX)?;
                    }
                }
                Ok(())
            })
            .unwrap(),
        )
    }

    fn packet(response: bool) -> Packet {
        let client = Ipv4Addr::new(192, 0, 2, 1);
        let server = Ipv4Addr::new(192, 0, 2, 2);
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: if response { server } else { client },
            destination: if response { client } else { server },
            ..Default::default()
        });
        packet
    }

    fn frame(seconds: u64, packet: Packet) -> Frame {
        let built = Builder::new(registry())
            .build(packet, Default::default(), Default::default())
            .unwrap();
        Frame::new(
            UNIX_EPOCH + Duration::from_secs(seconds),
            LinkType::RAW,
            built.bytes,
        )
        .unwrap()
    }

    fn udp(seconds: u64, payload: &[u8]) -> Frame {
        let mut packet = packet(false);
        packet.push(Udp {
            source_port: 40000,
            destination_port: 40001,
            ..Default::default()
        });
        packet.push(Raw::new(payload.to_vec()));
        frame(seconds, packet)
    }

    fn tcp(
        seconds: u64,
        response: bool,
        client_port: u16,
        sequence: u32,
        acknowledgment: u32,
        flags: u16,
        window: u16,
    ) -> Frame {
        let mut packet = packet(response);
        packet.push(Tcp {
            source_port: if response { 40001 } else { client_port },
            destination_port: if response { client_port } else { 40001 },
            sequence,
            acknowledgment,
            flags,
            window,
            ..Default::default()
        });
        frame(seconds, packet)
    }

    fn collect(frames: &[Frame], lifecycle: Lifecycle) -> (Vec<Finding>, Summary) {
        let mut writer = Writer::new(Vec::new(), Format::Pcap, LinkType::RAW).unwrap();
        for frame in frames {
            writer.write_frame(frame).unwrap();
        }
        let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
        let direct = matches!(lifecycle, Lifecycle::Direct);
        let now = Instant::now();
        let options = analysis::Options {
            plan: Plan {
                ip_reassembly: direct,
                tcp_index: direct,
                udp_index: direct,
            },
            deadline: Some(Arc::new(Deadline::with_time_source(
                Duration::from_secs(30),
                move || now,
            ))),
            tcp_events: direct,
            limits: analysis::Limits {
                max_frames: 16,
                max_bytes: 32 * 1024,
                max_frame_bytes: 512,
                max_duration: Duration::MAX,
                tcp: analysis::reassembly::tcp::Limits {
                    idle_expiry: Duration::from_secs(60),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let mut findings = Vec::new();
        match lifecycle {
            Lifecycle::Session => {
                let outcome = Session::new(registry(), options, Collector::new())
                    .run(
                        &mut reader,
                        |_| Ok(()),
                        |finding| {
                            findings.push(finding);
                            Ok(())
                        },
                    )
                    .unwrap();
                (findings, outcome.summary)
            }
            Lifecycle::Direct => {
                let mut collector = Collector::new();
                let run = analysis::run(&mut reader, registry(), &options, |record| {
                    findings.extend(<Collector as analysis::Collector>::observe(
                        &mut collector,
                        &record,
                    )?);
                    Ok(())
                })
                .unwrap();
                let (tail, summary) =
                    <Collector as analysis::Collector>::finish(collector, &run).unwrap();
                findings.extend(tail);
                (findings, summary)
            }
        }
    }

    #[test]
    fn capture_lengths_and_regressing_timestamps_publish_physical_warning_evidence() {
        let first = udp(100, b"first");
        let captured = first.captured_length();
        let original = captured + 9;
        let first = Frame::try_with_lengths(
            UNIX_EPOCH + Duration::from_secs(100),
            LinkType::RAW,
            Lengths { captured, original },
            first.bytes().clone(),
        )
        .unwrap();
        let frames = [first, udp(99, b"second")];
        for lifecycle in [Lifecycle::Session, Lifecycle::Direct] {
            let (findings, summary) = collect(&frames, lifecycle);
            let [truncated, regression] = findings.as_slice() else {
                panic!("expected the supplied capture-length and timestamp warnings")
            };
            assert_eq!(truncated.code, "capture.frame_truncated");
            assert_eq!(truncated.severity, Severity::Warning);
            assert_eq!(truncated.number, 1);
            assert_eq!(truncated.stream, None);
            assert!(
                truncated
                    .message
                    .contains(&format!("captured {captured} of {original} bytes"))
            );
            assert_eq!(regression.code, "capture.clock_regression");
            assert_eq!(regression.severity, Severity::Warning);
            assert_eq!(regression.number, 2);
            assert_eq!(regression.stream, None);
            assert!(regression.message.contains("frame 2 timestamp regressed"));
            assert_eq!(
                (
                    summary.findings,
                    summary.errors,
                    summary.warnings,
                    summary.notes
                ),
                (2, 0, 2, 0)
            );
            assert_eq!(
                summary.codes,
                BTreeMap::from([
                    ("capture.frame_truncated", 1),
                    ("capture.clock_regression", 1),
                ])
            );
            assert_eq!(summary.clock.regressions, 1);
            assert_eq!(summary.clock.max_regression, Duration::from_secs(1));
            assert_eq!(summary.clock.max_forward_step, Duration::ZERO);
            assert_eq!(summary.clock.max_forward_step_frame, None);
        }
    }

    #[test]
    fn tcp_windows_and_terminal_handshakes_keep_distinct_stream_evidence_and_totals() {
        // TCP sequence space and receive windows, checked 2026-10-25.
        // https://www.rfc-editor.org/rfc/rfc9293.html#section-3.3.1
        // https://www.rfc-editor.org/rfc/rfc9293.html#section-3.8.6
        let frames = [
            tcp(100, false, 40000, 100, 0, Tcp::SYN, 0),
            tcp(101, false, 40002, 300, 0, Tcp::SYN, 4096),
            tcp(102, true, 40002, 700, 301, Tcp::SYN | Tcp::ACK, 4096),
            tcp(103, false, 40002, 301, 701, Tcp::ACK, 4096),
            tcp(104, true, 40002, 701, 301, Tcp::ACK, 0),
        ];
        for lifecycle in [Lifecycle::Session, Lifecycle::Direct] {
            let (findings, summary) = collect(&frames, lifecycle);
            assert_eq!(findings.len(), 4);
            let first_window = findings
                .iter()
                .find(|finding| finding.code == "tcp.zero_window" && finding.number == 1)
                .unwrap();
            let second_window = findings
                .iter()
                .find(|finding| finding.code == "tcp.zero_window" && finding.number == 5)
                .unwrap();
            let unanswered = findings
                .iter()
                .find(|finding| finding.code == "tcp.handshake_unanswered")
                .unwrap();
            let open = findings
                .iter()
                .find(|finding| finding.code == "tcp.not_closed_at_end")
                .unwrap();
            assert_eq!(first_window.severity, Severity::Warning);
            assert_eq!(
                first_window.message,
                "192.0.2.1:40000 advertises a zero receive window"
            );
            assert_eq!(second_window.severity, Severity::Warning);
            assert_eq!(
                second_window.message,
                "192.0.2.2:40001 advertises a zero receive window"
            );
            let first_stream = first_window.stream.unwrap();
            let second_stream = second_window.stream.unwrap();
            assert_eq!(first_stream.transport, StreamTransport::Tcp);
            assert_eq!(second_stream.transport, StreamTransport::Tcp);
            assert_ne!(first_stream, second_stream);
            assert_eq!(unanswered.stream, Some(first_stream));
            assert_eq!(unanswered.number, 5);
            assert_eq!(unanswered.severity, Severity::Warning);
            assert_eq!(
                unanswered.message,
                "the SYN from 192.0.2.1:40000 never received a SYN-ACK"
            );
            assert_eq!(open.stream, Some(second_stream));
            assert_eq!(open.number, 5);
            assert_eq!(open.severity, Severity::Info);
            assert_eq!(
                open.message,
                "the connection opened by 192.0.2.1:40002 never saw a FIN or RST"
            );
            assert_eq!(
                (
                    summary.findings,
                    summary.errors,
                    summary.warnings,
                    summary.notes
                ),
                (4, 0, 3, 1)
            );
            assert_eq!(
                summary.codes,
                BTreeMap::from([
                    ("tcp.zero_window", 2),
                    ("tcp.handshake_unanswered", 1),
                    ("tcp.not_closed_at_end", 1),
                ])
            );
        }
    }
}
