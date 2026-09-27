// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One bounded analysis pass over a capture, driving the collector lifecycle.

use std::io::Read;
use std::sync::Arc;

use crate::error::BoundaryError;
use crate::filter::{Filter, Requirements};
use crate::registry::Registry;

use super::scope::Definition;
use super::{FrameRecord, IpEventRecord, Options, Plan, StreamRef, Summary, run_with_ip_events};
use crate::capture_file::Reader;

/// A stream index keeps IP reconstruction on: stream numbering follows reconstructed conversations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CollectorNeeds {
    pub tcp_stream: bool,
    pub udp_stream: bool,
    pub ip_reassembly: bool,
    pub tcp_events: bool,
    pub track_sources: bool,
}

impl CollectorNeeds {
    fn plan(self) -> Plan {
        Plan {
            ip_reassembly: self.ip_reassembly || self.tcp_stream || self.udp_stream,
            tcp_index: self.tcp_stream,
            udp_index: self.udp_stream,
        }
    }
}

/// `observe` failures cross the run as [`super::Error::Sink`]; `finish` and trailing-drain
/// failures surface as [`Error::Collector`](super::Error::Collector) after the run.
pub trait Collector {
    type Event;
    type Summary;

    /// Queried once, while the session is prepared.
    fn needs(&self) -> CollectorNeeds;

    fn scopes(&self) -> Vec<Definition> {
        Vec::new()
    }

    fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Self::Event>, BoundaryError>;

    fn finish(self, run: &Summary) -> Result<(Vec<Self::Event>, Self::Summary), BoundaryError>;
}

/// Lets a caller apply [`selected_absent`](Self::selected_absent) before [`finish`](Self::finish).
pub struct Pass<C: Collector> {
    pub run: Summary,
    collector: C,
    selector: Option<StreamRef>,
}

impl<C: Collector> Pass<C> {
    /// A selector was supplied but no frame matched it.
    #[must_use]
    pub fn selected_absent(&self) -> bool {
        self.selector.is_some() && self.run.frames_matched == 0
    }

    pub fn finish<F>(self, event_sink: &mut F) -> Result<Outcome<C>, super::Error>
    where
        F: FnMut(C::Event) -> Result<(), BoundaryError>,
    {
        let selected_absent = self.selected_absent();
        // Scope capture precedes finish, which consumes the collector.
        let scopes = self.collector.scopes();
        let (trailing, summary) = self
            .collector
            .finish(&self.run)
            .map_err(super::Error::Collector)?;
        for event in trailing {
            event_sink(event).map_err(super::Error::Collector)?;
        }
        Ok(Outcome {
            run: self.run,
            summary,
            scopes,
            selected_absent,
        })
    }
}

pub struct Outcome<C: Collector> {
    pub run: Summary,
    pub summary: C::Summary,
    pub scopes: Vec<Definition>,
    selected_absent: bool,
}

impl<C: Collector> Outcome<C> {
    /// A selector was supplied but no frame matched it.
    #[must_use]
    pub fn selected_absent(&self) -> bool {
        self.selected_absent
    }
}

/// Replaces `options.plan` and raises `tcp_events`/`track_sources` to cover collector needs.
pub struct Session<'a, C> {
    collector: C,
    options: Options<'a>,
    registry: Arc<Registry>,
    selector: Option<StreamRef>,
}

impl<'a, C: Collector> Session<'a, C> {
    /// `max_flows` bounds each transport capture-wide, so a plan that indexes at all indexes both.
    pub fn new(
        registry: Arc<Registry>,
        mut options: Options<'a>,
        collector: C,
        selector: Option<StreamRef>,
    ) -> Self {
        let requirements = options
            .filter
            .map_or_else(Requirements::default, Filter::requirements);
        let needs = collector.needs();
        if selector.is_some() {
            options.stream = selector;
        }
        options.plan = Plan::physical(requirements).union(needs.plan());
        if options.plan.tcp_index || options.plan.udp_index || options.stream.is_some() {
            options.plan = Plan::default();
        }
        options.tcp_events |= needs.tcp_events;
        options.track_sources |= needs.track_sources;
        Self {
            collector,
            selector: options.stream,
            options,
            registry,
        }
    }

    pub fn run<R, I, F>(
        self,
        reader: &mut Reader<R>,
        ip_sink: I,
        event_sink: F,
    ) -> Result<Outcome<C>, super::Error>
    where
        R: Read,
        I: FnMut(IpEventRecord) -> Result<(), BoundaryError>,
        F: FnMut(C::Event) -> Result<(), BoundaryError>,
    {
        let mut event_sink = event_sink;
        self.observe(reader, ip_sink, &mut event_sink)?
            .finish(&mut event_sink)
    }

    pub fn observe<R, I, F>(
        self,
        reader: &mut Reader<R>,
        ip_sink: I,
        event_sink: &mut F,
    ) -> Result<Pass<C>, super::Error>
    where
        R: Read,
        I: FnMut(IpEventRecord) -> Result<(), BoundaryError>,
        F: FnMut(C::Event) -> Result<(), BoundaryError>,
    {
        let mut collector = self.collector;
        let run = run_with_ip_events(reader, self.registry, &self.options, ip_sink, |record| {
            for event in collector.observe(&record)? {
                event_sink(event)?;
            }
            Ok(())
        })?;
        Ok(Pass {
            run,
            collector,
            selector: self.selector,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{Error as RunError, StreamTransport};
    use crate::build::{Builder, Options as BuildOptions};
    use crate::capture_file::Writer;
    use crate::codec::Context as BuildContext;
    use crate::error::Classified;
    use crate::error::{Classification, Kind};
    use crate::field::WireValue;
    use crate::filter::Limits as FilterLimits;
    use crate::frame::{Frame, LinkType};
    use crate::layer::Raw;
    use crate::packet::Packet;
    use crate::protocol::builtin;
    use crate::protocol::network::Ipv4;
    use crate::protocol::transport::{Tcp, Udp};
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::net::Ipv4Addr;
    use std::rc::Rc;
    use std::time::{Duration, SystemTime};

    type Log = Rc<RefCell<Vec<String>>>;

    #[derive(Clone, Copy, Debug, Default)]
    struct View {
        tcp_indexed: bool,
        udp_indexed: bool,
        sourced: bool,
        tcp_events: usize,
    }

    struct Probe {
        needs: CollectorNeeds,
        log: Log,
        views: Rc<RefCell<Vec<View>>>,
        fail_observe_at: Option<u64>,
        fail_finish: bool,
        trailing: Vec<u64>,
    }

    impl Probe {
        fn new(needs: CollectorNeeds, log: &Log, views: &Rc<RefCell<Vec<View>>>) -> Self {
            Self {
                needs,
                log: log.clone(),
                views: views.clone(),
                fail_observe_at: None,
                fail_finish: false,
                trailing: Vec::new(),
            }
        }
    }

    fn probe_error() -> BoundaryError {
        BoundaryError::new(
            "probe failed",
            Classification::new("probe.failed", Kind::Internal, None),
            Vec::new(),
        )
    }

    impl Collector for Probe {
        type Event = u64;
        type Summary = u64;

        fn needs(&self) -> CollectorNeeds {
            self.needs
        }

        fn scopes(&self) -> Vec<Definition> {
            self.log.borrow_mut().push("scopes".to_owned());
            Vec::new()
        }

        fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<u64>, BoundaryError> {
            self.log
                .borrow_mut()
                .push(format!("observe:{}", record.number));
            self.views.borrow_mut().push(View {
                tcp_indexed: record.tcp.and_then(|view| view.conversation).is_some(),
                udp_indexed: record.udp.and_then(|view| view.conversation).is_some(),
                sourced: record.physical_sources().is_some(),
                tcp_events: record.tcp_events.len(),
            });
            if self.fail_observe_at == Some(record.number) {
                return Err(probe_error());
            }
            Ok(vec![record.number])
        }

        fn finish(self, _run: &Summary) -> Result<(Vec<u64>, u64), BoundaryError> {
            self.log.borrow_mut().push("finish".to_owned());
            if self.fail_finish {
                return Err(probe_error());
            }
            Ok((self.trailing.clone(), 42))
        }
    }

    fn build(registry: &Arc<Registry>, packet: Packet, seconds: u64) -> Frame {
        let bytes = Builder::new(Arc::clone(registry))
            .build(packet, BuildContext::default(), BuildOptions::default())
            .expect("fixture packet builds")
            .bytes;
        Frame::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
            LinkType::IPV4,
            bytes,
        )
        .expect("fixture frame is valid")
    }

    fn udp_frame(registry: &Arc<Registry>, seconds: u64) -> Frame {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            protocol: WireValue::Exact(17),
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 50_000,
            destination_port: 9_999,
            ..Udp::default()
        });
        packet.push(Raw::new(vec![0_u8; 8]));
        build(registry, packet, seconds)
    }

    fn tcp_frame(registry: &Arc<Registry>, seconds: u64, flags: u16, sequence: u32) -> Frame {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            protocol: WireValue::Exact(6),
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        });
        packet.push(Tcp {
            source_port: 40_000,
            destination_port: 80,
            sequence,
            flags,
            ..Tcp::default()
        });
        packet.push(Raw::new(if flags & Tcp::SYN != 0 {
            Vec::new()
        } else {
            vec![0_u8; 8]
        }));
        build(registry, packet, seconds)
    }

    fn fragment_frame(registry: &Arc<Registry>, seconds: u64, identification: u16) -> Frame {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            identification,
            more_fragments: true,
            protocol: WireValue::Exact(17),
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        });
        packet.push(Raw::new(vec![0_u8; 8]));
        build(registry, packet, seconds)
    }

    fn reader_of(frames: &[Frame]) -> Reader<Cursor<Vec<u8>>> {
        let mut writer = Writer::pcap(Vec::new(), LinkType::IPV4).expect("writer initializes");
        for frame in frames {
            writer.write_frame(frame).expect("fixture frame writes");
        }
        Reader::new(Cursor::new(writer.into_inner())).expect("fixture capture reads")
    }

    fn compile(source: &str, registry: &Registry) -> Filter {
        Filter::compile(source, registry, FilterLimits::default()).expect("fixture filter compiles")
    }

    struct Driven {
        outcome: Outcome<Probe>,
        views: Vec<View>,
        log: Vec<String>,
    }

    fn drive(
        registry: &Arc<Registry>,
        frames: &[Frame],
        probe: Probe,
        filter: Option<&Filter>,
        selector: Option<StreamRef>,
    ) -> Result<Driven, RunError> {
        let mut reader = reader_of(frames);
        let options = Options {
            filter,
            ..Options::default()
        };
        let views = probe.views.clone();
        let log = probe.log.clone();
        let outcome = Session::new(registry.clone(), options, probe, selector).run(
            &mut reader,
            |_| Ok(()),
            |event| {
                log.borrow_mut().push(format!("event:{event}"));
                Ok(())
            },
        )?;
        Ok(Driven {
            outcome,
            views: views.take(),
            log: log.take(),
        })
    }

    fn expect_failure(result: Result<Driven, RunError>) -> RunError {
        match result {
            Ok(_) => panic!("the session succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn lifecycle_orders_observe_events_scopes_finish_and_trailing() {
        let registry = builtin::registry();
        let log = Log::default();
        let views = Rc::new(RefCell::new(Vec::new()));
        let mut probe = Probe::new(CollectorNeeds::default(), &log, &views);
        probe.trailing = vec![900, 901];

        let driven = drive(
            &registry,
            &[udp_frame(&registry, 0), udp_frame(&registry, 1)],
            probe,
            None,
            None,
        )
        .expect("session runs");

        assert_eq!(driven.outcome.summary, 42);
        assert_eq!(driven.outcome.run.frames_matched, 2);
        assert!(!driven.outcome.selected_absent());
        assert_eq!(
            driven.log,
            [
                "observe:1",
                "event:1",
                "observe:2",
                "event:2",
                "scopes",
                "finish",
                "event:900",
                "event:901",
            ],
            "frame events drain in order, scopes precede finish, trailing events follow"
        );
    }

    #[test]
    fn empty_selector_verdict_arrives_after_the_trailing_drain() {
        let registry = builtin::registry();
        let log = Log::default();
        let views = Rc::new(RefCell::new(Vec::new()));
        let mut probe = Probe::new(CollectorNeeds::default(), &log, &views);
        probe.trailing = vec![7];

        let driven = drive(
            &registry,
            &[udp_frame(&registry, 0)],
            probe,
            None,
            Some(StreamRef {
                transport: StreamTransport::Tcp,
                index: 42,
            }),
        )
        .expect("session runs");

        assert!(driven.outcome.selected_absent());
        assert_eq!(
            driven.log,
            ["scopes", "finish", "event:7"],
            "no frame matched; the verdict still follows the trailing drain"
        );
    }

    #[test]
    fn split_phases_let_the_verdict_precede_finish() {
        let registry = builtin::registry();
        let log = Log::default();
        let views = Rc::new(RefCell::new(Vec::new()));
        let probe = Probe::new(CollectorNeeds::default(), &log, &views);
        let mut reader = reader_of(&[udp_frame(&registry, 0)]);
        let mut sink = |event: u64| -> Result<(), BoundaryError> {
            log.borrow_mut().push(format!("event:{event}"));
            Ok(())
        };

        let pass = Session::new(
            registry,
            Options::default(),
            probe,
            Some(StreamRef {
                transport: StreamTransport::Tcp,
                index: 42,
            }),
        )
        .observe(&mut reader, |_| Ok(()), &mut sink)
        .expect("frames observe");

        assert!(pass.selected_absent());
        assert_eq!(
            pass.run.frames_matched, 0,
            "the run summary is available before finish"
        );
        drop(pass);
        assert!(log.borrow().is_empty(), "neither scopes nor finish ran");
    }

    #[test]
    fn narrowing_keeps_only_the_stages_anyone_reads() {
        let registry = builtin::registry();
        let frames = [
            tcp_frame(&registry, 0, Tcp::SYN, 100),
            udp_frame(&registry, 1),
        ];
        let log = Log::default();
        let views = Rc::new(RefCell::new(Vec::new()));
        let driven = drive(
            &registry,
            &frames,
            Probe::new(CollectorNeeds::default(), &log, &views),
            None,
            None,
        )
        .expect("session runs");

        assert!(
            driven
                .views
                .iter()
                .all(|view| !view.tcp_indexed && !view.udp_indexed && !view.sourced),
            "no stage ran that nothing reads"
        );
        assert!(
            driven.outcome.run.trailing_tcp_events.is_empty(),
            "TCP reassembly stayed off"
        );
    }

    #[test]
    fn declared_needs_raise_indexing_reassembly_events_and_sources() {
        let registry = builtin::registry();
        let frames = [
            tcp_frame(&registry, 0, Tcp::SYN, 100),
            tcp_frame(&registry, 1, Tcp::ACK, 101),
            udp_frame(&registry, 2),
        ];
        let log = Log::default();
        let views = Rc::new(RefCell::new(Vec::new()));
        let driven = drive(
            &registry,
            &frames,
            Probe::new(
                CollectorNeeds {
                    tcp_stream: true,
                    tcp_events: true,
                    track_sources: true,
                    ..CollectorNeeds::default()
                },
                &log,
                &views,
            ),
            None,
            None,
        )
        .expect("session runs");

        assert_eq!(driven.views.len(), 3);
        let [syn, data, udp] = driven.views[..] else {
            panic!("three frames observed");
        };
        assert!(syn.tcp_indexed && syn.sourced);
        assert!(
            data.tcp_indexed && data.sourced && data.tcp_events > 0,
            "the payload frame carried a reassembly delivery"
        );
        assert!(
            udp.udp_indexed,
            "conversation accounting is indivisible: the UDP frame is indexed \
             even though the collector reads only TCP"
        );
        assert!(
            !driven.outcome.run.trailing_tcp_events.is_empty(),
            "the open flow flushes at end of capture"
        );
    }

    #[test]
    fn a_stream_selector_keeps_exactly_the_frames_its_filter_text_would() {
        let registry = builtin::registry();
        let frames = [
            tcp_frame(&registry, 0, Tcp::SYN, 100),
            udp_frame(&registry, 1),
            tcp_frame(&registry, 2, Tcp::ACK, 101),
            udp_frame(&registry, 3),
        ];
        for (selector, text) in [
            (
                StreamRef {
                    transport: StreamTransport::Tcp,
                    index: 0,
                },
                "tcp.stream == 0",
            ),
            (
                StreamRef {
                    transport: StreamTransport::Udp,
                    index: 0,
                },
                "udp.stream == 0",
            ),
        ] {
            let matched = |filter: Option<&Filter>, selector: Option<StreamRef>| {
                let log = Log::default();
                let views = Rc::new(RefCell::new(Vec::new()));
                let driven = drive(
                    &registry,
                    &frames,
                    Probe::new(CollectorNeeds::default(), &log, &views),
                    filter,
                    selector,
                )
                .expect("session runs");
                assert!(!driven.outcome.selected_absent(), "{text}");
                driven
                    .log
                    .iter()
                    .filter(|entry| entry.starts_with("observe:"))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            let filter = compile(text, &registry);
            let by_selector = matched(None, Some(selector));
            assert_eq!(by_selector.len(), 2, "{text}: {by_selector:?}");
            assert_eq!(by_selector, matched(Some(&filter), None), "{text}");
        }
    }

    #[test]
    fn filter_requirements_union_with_collector_needs() {
        let registry = builtin::registry();
        let filter = compile("udp.stream == 0 || frame.number == 1", &registry);
        let frames = [
            tcp_frame(&registry, 0, Tcp::SYN, 100),
            udp_frame(&registry, 1),
        ];
        let log = Log::default();
        let views = Rc::new(RefCell::new(Vec::new()));
        let driven = drive(
            &registry,
            &frames,
            Probe::new(CollectorNeeds::default(), &log, &views),
            Some(&filter),
            None,
        )
        .expect("session runs");

        assert_eq!(driven.views.len(), 2, "both frames matched the filter");
        assert!(
            driven.views[0].tcp_indexed && driven.views[1].udp_indexed,
            "a filter reading udp.stream still runs capture-global TCP \
             accounting: indexing is all-or-nothing per run"
        );
    }

    #[test]
    fn ip_events_forward_ahead_of_the_records_they_reveal() {
        let registry = builtin::registry();
        let log = Log::default();
        let views = Rc::new(RefCell::new(Vec::new()));
        let probe = Probe::new(
            CollectorNeeds {
                ip_reassembly: true,
                ..CollectorNeeds::default()
            },
            &log,
            &views,
        );
        let frames = [
            fragment_frame(&registry, 0, 7),
            // Past the default idle expiry, so this frame's sweep retires the datagram first.
            udp_frame(&registry, 40),
        ];
        let mut reader = reader_of(&frames);
        let ip_log = log.clone();

        Session::new(registry, Options::default(), probe, None)
            .run(
                &mut reader,
                |_| {
                    ip_log.borrow_mut().push("ip".to_owned());
                    Ok(())
                },
                |event| {
                    log.borrow_mut().push(format!("event:{event}"));
                    Ok(())
                },
            )
            .expect("session runs");

        let log = log.borrow();
        let ip = log
            .iter()
            .position(|entry| entry == "ip")
            .expect("an expiry event was delivered");
        assert!(
            log[..ip].iter().all(|entry| entry != "observe:2")
                && log[ip..].iter().any(|entry| entry == "observe:2"),
            "the expiry event arrived before the frame-2 record: {log:?}"
        );
    }

    #[test]
    fn observe_failures_surface_as_run_errors() {
        let registry = builtin::registry();
        let log = Log::default();
        let views = Rc::new(RefCell::new(Vec::new()));
        let mut probe = Probe::new(CollectorNeeds::default(), &log, &views);
        probe.fail_observe_at = Some(2);

        let error = expect_failure(drive(
            &registry,
            &[udp_frame(&registry, 0), udp_frame(&registry, 1)],
            probe,
            None,
            None,
        ));

        match error {
            RunError::Sink { number, .. } => {
                assert_eq!(number, 2, "the failure is attributed to its frame");
            }
            other => panic!("expected a run sink error, got {other:?}"),
        }
        assert_eq!(
            error.classification().code,
            "probe.failed",
            "the collector's classification survives the boundary"
        );
    }

    #[test]
    fn finish_failures_surface_as_collector_errors() {
        let registry = builtin::registry();
        let log = Log::default();
        let views = Rc::new(RefCell::new(Vec::new()));
        let mut probe = Probe::new(CollectorNeeds::default(), &log, &views);
        probe.fail_finish = true;

        let error = expect_failure(drive(
            &registry,
            &[udp_frame(&registry, 0)],
            probe,
            None,
            None,
        ));

        match error {
            RunError::Collector(source) => {
                assert_eq!(source.classification().code, "probe.failed");
            }
            other => panic!("expected a collector error, got {other:?}"),
        }
    }

    #[test]
    fn sink_failures_keep_their_phase_domain() {
        let registry = builtin::registry();
        let frames = [udp_frame(&registry, 0)];
        let log = Log::default();
        let views = Rc::new(RefCell::new(Vec::new()));
        let probe = Probe::new(CollectorNeeds::default(), &log, &views);
        let mut reader = reader_of(&frames);
        let mut failing = |event: u64| -> Result<(), BoundaryError> {
            if event == 1 {
                return Err(probe_error());
            }
            Ok(())
        };
        let error = match Session::new(registry.clone(), Options::default(), probe, None).observe(
            &mut reader,
            |_| Ok(()),
            &mut failing,
        ) {
            Ok(_) => panic!("the in-run sink failed to fail"),
            Err(error) => error,
        };
        match error {
            RunError::Sink { number: 1, .. } => {}
            other => panic!("expected a run sink error at frame 1, got {other:?}"),
        }

        let log = Log::default();
        let views = Rc::new(RefCell::new(Vec::new()));
        let mut probe = Probe::new(CollectorNeeds::default(), &log, &views);
        probe.trailing = vec![900];
        let mut reader = reader_of(&frames);
        let pass = Session::new(registry, Options::default(), probe, None)
            .observe(&mut reader, |_| Ok(()), &mut |_: u64| Ok(()))
            .expect("frames observe");
        let mut failing = |event: u64| -> Result<(), BoundaryError> {
            if event == 900 {
                return Err(probe_error());
            }
            Ok(())
        };
        match pass.finish(&mut failing) {
            Err(RunError::Collector(source)) => {
                assert_eq!(source.classification().code, "probe.failed");
            }
            Err(other) => panic!("expected a collector error, got {other:?}"),
            Ok(_) => panic!("expected a collector error; the drain succeeded"),
        }
    }

    #[test]
    fn needs_map_to_the_plan_they_read() {
        assert_eq!(
            CollectorNeeds::default().plan(),
            Plan {
                ip_reassembly: false,
                tcp_index: false,
                udp_index: false,
            }
        );
        assert_eq!(
            CollectorNeeds {
                tcp_stream: true,
                ..CollectorNeeds::default()
            }
            .plan(),
            Plan {
                ip_reassembly: true,
                tcp_index: true,
                udp_index: false,
            },
            "indexing keeps IP reconstruction for canonical numbering"
        );
        assert_eq!(
            Plan::physical(Requirements {
                udp_stream: true,
                ..Requirements::default()
            })
            .union(
                CollectorNeeds {
                    tcp_stream: true,
                    ..CollectorNeeds::default()
                }
                .plan()
            ),
            Plan {
                ip_reassembly: true,
                tcp_index: true,
                udp_index: true,
            },
            "filter and collector stages union without renumbering streams"
        );
    }
}
