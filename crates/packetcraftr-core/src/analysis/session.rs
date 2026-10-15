// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One bounded analysis pass over a capture, driving the collector lifecycle.

use std::io::Read;
use std::sync::Arc;

use crate::error::BoundaryError;
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
}

impl<'a, C: Collector> Session<'a, C> {
    /// `max_flows` bounds each transport capture-wide, so a plan that indexes at all indexes both.
    pub fn new(registry: Arc<Registry>, mut options: Options<'a>, collector: C) -> Self {
        let needs = collector.needs();
        options.plan = Plan::for_collector(needs, options.filter, options.stream);
        options.tcp_events |= needs.tcp_events;
        options.track_sources |= needs.track_sources;
        Self {
            collector,
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
            selector: self.options.stream,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        build, capture_file, expression,
        frame::{Frame, LinkType},
        protocol::builtin,
    };
    use std::{
        io::Cursor,
        time::{Duration, UNIX_EPOCH},
    };

    struct Records {
        fail: bool,
    }
    impl Collector for Records {
        type Event = u64;
        type Summary = ();
        fn needs(&self) -> CollectorNeeds {
            CollectorNeeds::default()
        }
        fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<u64>, BoundaryError> {
            if self.fail {
                return Err(BoundaryError::new(
                    "collector refused frame",
                    crate::error::Classification::new(
                        "test.collector",
                        crate::error::Kind::Internal,
                        None,
                    ),
                    Vec::new(),
                ));
            }
            Ok(vec![record.number])
        }
        fn finish(self, _: &Summary) -> Result<(Vec<u64>, ()), BoundaryError> {
            Ok((Vec::new(), ()))
        }
    }

    fn capture() -> Reader<Cursor<Vec<u8>>> {
        let registry = builtin::registry();
        let mut bytes = Vec::new();
        {
            let mut writer =
                capture_file::Writer::new(&mut bytes, capture_file::Format::Pcap, LinkType::IPV4)
                    .unwrap();
            for (index, port) in [9, 80, 9].into_iter().enumerate() {
                let packet = expression::parse(
                    &format!("ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=12345,dport={port})/raw(text=fixture)"),
                    &registry, expression::Limits::default(),
                ).unwrap();
                let built = build::Builder::new(registry.clone())
                    .build(packet, Default::default(), Default::default())
                    .unwrap();
                writer
                    .write_frame(
                        &Frame::new(
                            UNIX_EPOCH + Duration::from_secs(index as u64),
                            LinkType::IPV4,
                            built.bytes,
                        )
                        .unwrap(),
                    )
                    .unwrap();
            }
        }
        Reader::new(Cursor::new(bytes)).unwrap()
    }

    #[test]
    fn selection_comes_from_options_after_capture_wide_indexing() {
        let registry = builtin::registry();
        let filter =
            crate::filter::Filter::compile("udp.stream == 1", &registry, Default::default())
                .unwrap();
        let options = Options {
            stream: Some(StreamRef {
                transport: super::super::StreamTransport::Udp,
                index: 1,
            }),
            filter: Some(&filter),
            ..Default::default()
        };
        let mut records = Vec::new();
        let outcome = Session::new(registry, options, Records { fail: false })
            .run(
                &mut capture(),
                |_| Ok(()),
                |number| {
                    records.push(number);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(records, [2]);
        assert_eq!(outcome.run.frames_read, 3);
        assert!(!outcome.selected_absent());
    }

    #[test]
    fn missing_stream_is_reported_and_reader_deadline_is_restored_on_both_paths() {
        for fail in [false, true] {
            let parent = Arc::new(crate::budget::Deadline::new(Duration::from_secs(30)));
            let mut reader = capture().with_deadline(parent.clone());
            let result = Session::new(builtin::registry(), Options::default(), Records { fail })
                .run(&mut reader, |_| Ok(()), |_| Ok(()));
            assert_eq!(result.is_err(), fail);
            assert!(Arc::ptr_eq(&reader.deadline().unwrap(), &parent));
        }
        let options = Options {
            stream: Some(StreamRef {
                transport: super::super::StreamTransport::Udp,
                index: 9,
            }),
            ..Default::default()
        };
        let outcome = Session::new(builtin::registry(), options, Records { fail: false })
            .run(&mut capture(), |_| Ok(()), |_| Ok(()))
            .unwrap();
        assert!(outcome.selected_absent());
        assert_eq!(outcome.run.frames_matched, 0);
    }
}
