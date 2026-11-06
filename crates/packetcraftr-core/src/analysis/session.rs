// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One bounded analysis pass over a capture, driving the collector lifecycle.

use std::io::Read;
use std::sync::Arc;

use crate::budget::Deadline;
use crate::error::BoundaryError;
use crate::registry::Registry;

use super::scope::Definition;
use super::{FrameRecord, IpEventRecord, Options, Plan, StreamRef, Summary};
use crate::capture_file::Reader;

/// The `Collector` glue shared by the application analyses whose inherent `observe`
/// and `finalize` report their own `Error`. Expands where those items are in scope.
macro_rules! application_collector {
    ($($need:ident: $value:expr),* $(,)?) => {
        impl Collector {
            pub fn finish(self, run: &RunSummary) -> Result<(Vec<Event>, Summary), Error> {
                let mut output = Vec::new();
                let summary = self.finalize(
                    run,
                    || Ok(()),
                    |events| {
                        output.extend(events);
                        Ok(())
                    },
                )?;
                Ok((output, summary))
            }
        }

        impl session::Collector for Collector {
            type Event = Event;
            type Summary = Summary;

            fn needs(&self) -> CollectorNeeds {
                CollectorNeeds {
                    tcp_stream: true,
                    tcp_events: true,
                    track_sources: true,
                    $($need: $value,)*
                    ..CollectorNeeds::default()
                }
            }

            fn scopes(&self) -> Vec<Definition> {
                Self::scopes(self).cloned().collect()
            }

            fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, BoundaryError> {
                Self::observe(self, record).map_err(BoundaryError::from_error)
            }

            fn finish(
                self,
                run: &RunSummary,
                deadline: &crate::budget::Deadline,
                event_sink: &mut dyn FnMut(Event) -> Result<(), BoundaryError>,
            ) -> Result<Summary, BoundaryError> {
                self.finalize(
                    run,
                    || session::check(deadline).map_err(Error::Output),
                    |events| session::deliver(deadline, events, event_sink).map_err(Error::Output),
                )
                .map_err(BoundaryError::from_error)
            }
        }
    };
}
pub(super) use application_collector;

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

    /// Finalize under the original run control, delivering terminal events in
    /// order through `event_sink`. Check the deadline during large
    /// finalizations instead of retaining the complete terminal event list.
    /// A synchronous callback must cooperate: it cannot be interrupted while
    /// it is blocked.
    fn finish(
        self,
        run: &Summary,
        deadline: &Deadline,
        event_sink: &mut dyn FnMut(Self::Event) -> Result<(), BoundaryError>,
    ) -> Result<Self::Summary, BoundaryError>;
}

pub(super) fn check(deadline: &Deadline) -> Result<(), BoundaryError> {
    deadline.enforce().map_err(BoundaryError::from_error)
}

pub(super) fn deliver<E>(
    deadline: &Deadline,
    events: impl IntoIterator<Item = E>,
    event_sink: &mut dyn FnMut(E) -> Result<(), BoundaryError>,
) -> Result<(), BoundaryError> {
    check(deadline)?;
    for event in events {
        check(deadline)?;
        event_sink(event)?;
        check(deadline)?;
    }
    Ok(())
}

/// Lets a caller apply [`selected_absent`](Self::selected_absent) before [`finish`](Self::finish).
pub struct Pass<C: Collector> {
    pub run: Summary,
    collector: C,
    selector: Option<StreamRef>,
    deadline: Arc<Deadline>,
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
        check(&self.deadline).map_err(super::Error::Collector)?;
        // Scope capture precedes finish, which consumes the collector.
        let scopes = self.collector.scopes();
        check(&self.deadline).map_err(super::Error::Collector)?;
        let summary = self
            .collector
            .finish(&self.run, &self.deadline, event_sink)
            .map_err(super::Error::Collector)?;
        check(&self.deadline).map_err(super::Error::Collector)?;
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

/// Caller-owned inputs for one [`Session`] run. The plan, TCP event
/// delivery, and source tracking a run needs are derived from the
/// collector's [`CollectorNeeds`], not supplied here.
#[derive(Clone, Debug, Default)]
pub struct SessionOptions<'a> {
    /// Shared invocation ceiling; a local phase limit may tighten it.
    pub deadline: Option<Arc<Deadline>>,
    pub cancellation: Option<crate::budget::Cancellation>,
    pub filter: Option<&'a crate::filter::Filter>,
    pub stream: Option<StreamRef>,
    pub time_bounds: Option<crate::frame::TimeBounds>,
    pub ip_overlap: crate::analysis::reassembly::ip::OverlapPolicy,
    pub limits: super::Limits,
}

pub struct Session<'a, C> {
    collector: C,
    options: Options<'a>,
    registry: Arc<Registry>,
}

impl<'a, C: Collector> Session<'a, C> {
    /// `max_flows` bounds each transport capture-wide, so a plan that indexes at all indexes both.
    pub fn new(registry: Arc<Registry>, options: SessionOptions<'a>, collector: C) -> Self {
        let needs = collector.needs();
        let options = Options {
            plan: Plan::for_collector(needs, options.filter, options.stream),
            deadline: options.deadline,
            track_sources: needs.track_sources,
            cancellation: options.cancellation,
            filter: options.filter,
            stream: options.stream,
            time_bounds: options.time_bounds,
            tcp_events: needs.tcp_events,
            ip_overlap: options.ip_overlap,
            limits: options.limits,
        };
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
        let (run, deadline) = super::pipeline::run_controlled(
            reader,
            self.registry,
            &self.options,
            ip_sink,
            |record, deadline| {
                let events = collector.observe(&record)?;
                deliver(deadline, events, event_sink)?;
                Ok(())
            },
        )?;
        Ok(Pass {
            run,
            collector,
            selector: self.options.stream,
            deadline,
        })
    }
}
