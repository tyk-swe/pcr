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

    /// Finalize under the original run control, delivering terminal events in
    /// order. Override this for large finalizers to check control internally
    /// and avoid retaining the complete terminal event list. The default keeps
    /// existing collectors compatible. A synchronous callback must cooperate:
    /// it cannot be interrupted while it is blocked.
    fn finish_controlled(
        self,
        run: &Summary,
        deadline: &Deadline,
        event_sink: &mut dyn FnMut(Self::Event) -> Result<(), BoundaryError>,
    ) -> Result<Self::Summary, BoundaryError>
    where
        Self: Sized,
    {
        check(deadline)?;
        let (events, summary) = self.finish(run)?;
        deliver(deadline, events, event_sink)?;
        Ok(summary)
    }
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
            .finish_controlled(&self.run, &self.deadline, event_sink)
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
