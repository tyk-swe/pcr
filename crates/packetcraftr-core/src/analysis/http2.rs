// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Sourced cleartext HTTP/2 and h2c analysis over reassembled TCP.

mod budget;
mod buffer;
mod connection;
mod headers;
mod limits;
mod model;
mod settings;
mod side;
mod stream;
mod upgrade;

mod error;

#[cfg(test)]
mod tests;

pub use error::Error;
pub use limits::{
    Limits, MAX_ACTIVE_STREAMS, MAX_BODY_BYTES, MAX_CONTINUATIONS, MAX_FRAME_BYTES, MAX_FRAMES,
    MAX_HEADER_BLOCK_BYTES, MAX_HEADER_BYTES, MAX_HEADERS, MAX_PENDING_SETTINGS, MAX_STREAMS,
    MAX_TABLE_BYTES,
};
pub use model::{
    Certainty, Connection, Event, Frame, FrameBody, Header, Issue, IssueScope, Message,
    MessageKind, PeerSettings, Startup, Status, Summary,
};

use crate::budget::Deadline;
use crate::error::BoundaryError;
use budget::{Budget, Context};
use connection::{ConnectionState, Phase};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::{
    FrameRecord, Summary as RunSummary,
    application::{self, TcpSources},
    reassembly::tcp::ScopedFlowKey,
    scope::Definition,
    session::{self, CollectorNeeds},
};

type ConnectionKey = (u64, u64);

struct Resources {
    app_limits: application::Limits,
    limits: Limits,
    deadline: Option<Arc<Deadline>>,
    budget: Budget,
}

impl Resources {
    fn context<'a>(&'a mut self, out: &'a mut Vec<Event>) -> Context<'a> {
        Context {
            limits: &self.limits,
            app: &self.app_limits,
            deadline: self.deadline.as_deref(),
            budget: &mut self.budget,
            out,
        }
    }

    fn enforce_deadline(&self) -> Result<(), Error> {
        if let Some(deadline) = self.deadline.as_deref() {
            deadline.enforce()?;
        }
        Ok(())
    }
}

pub struct Collector {
    resources: Resources,
    tcp: TcpSources,
    // Boxed to keep B-tree nodes small; connection state is large.
    connections: BTreeMap<ConnectionKey, Box<ConnectionState>>,
    flow_index: BTreeMap<ScopedFlowKey, ConnectionKey>,
    failed: bool,
}

impl Collector {
    pub fn new(
        application: application::Limits,
        ports: impl IntoIterator<Item = u16>,
        limits: Limits,
    ) -> Result<Self, Error> {
        application.validate()?;
        let ports = application::normalize_ports(ports, "http2_ports")?;
        limits.validate()?;
        Ok(Self {
            resources: Resources {
                app_limits: application,
                limits,
                deadline: None,
                budget: Budget::default(),
            },
            tcp: TcpSources::new(ports, application),
            connections: BTreeMap::new(),
            flow_index: BTreeMap::new(),
            failed: false,
        })
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: Arc<Deadline>) -> Self {
        self.resources.deadline = Some(deadline);
        self
    }

    pub fn scopes(&self) -> impl Iterator<Item = &Definition> {
        self.tcp.scopes.values()
    }

    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let mut out = Vec::new();
        if let Err(error) = self.observe_into(record, &mut out) {
            self.failed = true;
            self.connections.clear();
            self.flow_index.clear();
            return Err(error);
        }
        Ok(out)
    }

    fn observe_into(
        &mut self,
        record: &FrameRecord<'_>,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        self.resources.enforce_deadline()?;
        for event in self.tcp.observe(record)? {
            self.dispatch(event, record.number, out)?;
        }
        Ok(())
    }

    fn dispatch(
        &mut self,
        event: application::Event,
        number: u64,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        match event {
            application::Event::Data(delivery) => {
                let key = (delivery.stream, delivery.generation);
                if let Some(&old) = self.flow_index.get(&delivery.flow)
                    && old != key
                    && let Some(mut conn) = self.connections.remove(&old)
                {
                    self.flow_index.retain(|_, k| *k != old);
                    conn.number = number;
                    if !conn.done && !matches!(conn.phase, Phase::Dead) {
                        conn.terminate(
                            &delivery.flow,
                            Status::Evicted,
                            "generation_replaced",
                            "the TCP tuple was reused for a newer connection",
                            &mut self.resources.context(out),
                        )?;
                    }
                    conn.finish(&mut self.resources.context(out))?;
                }
                self.flow_index.insert(delivery.flow.clone(), key);
                let conn = self.connections.entry(key).or_insert_with(|| {
                    Box::new(ConnectionState::new(
                        delivery.stream,
                        delivery.generation,
                        delivery.flow.clone(),
                    ))
                });
                conn.data(&delivery, number, &mut self.resources.context(out))
            }
            application::Event::Gap { flow, .. } => self.fail_flow(
                &flow,
                number,
                Status::Gap,
                "tcp_gap",
                "a TCP sequence gap invalidated the byte stream",
                out,
            ),
            application::Event::Conflict { flow, .. } => self.fail_flow(
                &flow,
                number,
                Status::Conflict,
                "tcp_conflict",
                "conflicting TCP retransmissions invalidated the byte stream",
                out,
            ),
            application::Event::Evicted { flow, .. } => self.fail_flow(
                &flow,
                number,
                Status::Evicted,
                "tcp_evicted",
                "reassembly state was evicted before the stream completed",
                out,
            ),
            application::Event::Closed { flow, reset, .. } => {
                let Some(conn) = self
                    .flow_index
                    .get(&flow)
                    .or_else(|| self.flow_index.get(&flow.reverse()))
                    .and_then(|key| self.connections.get_mut(key))
                    .filter(|conn| conn.has_flow(&flow) || conn.has_flow(&flow.reverse()))
                else {
                    return Ok(());
                };
                conn.number = number;
                conn.close(&flow, reset, &mut self.resources.context(out))
            }
        }
    }

    fn fail_flow(
        &mut self,
        flow: &ScopedFlowKey,
        number: u64,
        status: Status,
        code: &'static str,
        detail: &'static str,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let keys: BTreeSet<ConnectionKey> = self
            .flow_index
            .iter()
            .filter(|(f, _)| *f == flow || f.reverse() == *flow)
            .map(|(_, key)| *key)
            .collect();
        for key in keys {
            if let Some(conn) = self.connections.get_mut(&key) {
                conn.number = number;
                conn.terminate(flow, status, code, detail, &mut self.resources.context(out))?;
            }
        }
        Ok(())
    }

    pub fn finish(self, run: &RunSummary) -> Result<(Vec<Event>, Summary), Error> {
        let mut out = Vec::new();
        let summary = self.finalize(run, |events| {
            out.extend(events);
            Ok(())
        })?;
        Ok((out, summary))
    }

    fn finalize(
        mut self,
        run: &RunSummary,
        mut emit: impl FnMut(Vec<Event>) -> Result<(), Error>,
    ) -> Result<Summary, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        self.resources.enforce_deadline()?;
        for event in self
            .tcp
            .trailing(&run.trailing_tcp_events, run.frames_read)?
        {
            self.resources.enforce_deadline()?;
            let mut out = Vec::new();
            if !matches!(event, application::Event::Evicted { .. }) {
                self.dispatch(event, run.frames_read, &mut out)?;
            }
            emit(out)?;
        }
        for mut conn in std::mem::take(&mut self.connections).into_values() {
            self.resources.enforce_deadline()?;
            let mut out = Vec::new();
            conn.number = run.frames_read;
            conn.finish(&mut self.resources.context(&mut out))?;
            emit(out)?;
        }
        self.resources.enforce_deadline()?;
        Ok(self.resources.budget.into_summary())
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
            ..CollectorNeeds::default()
        }
    }

    fn scopes(&self) -> Vec<Definition> {
        Self::scopes(self).cloned().collect()
    }

    fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, BoundaryError> {
        Self::observe(self, record).map_err(BoundaryError::from_error)
    }

    fn finish(self, run: &RunSummary) -> Result<(Vec<Event>, Summary), BoundaryError> {
        Self::finish(self, run).map_err(BoundaryError::from_error)
    }

    fn finish_controlled(
        mut self,
        run: &RunSummary,
        deadline: &Deadline,
        event_sink: &mut dyn FnMut(Event) -> Result<(), BoundaryError>,
    ) -> Result<Summary, BoundaryError> {
        self.resources.deadline = Some(Arc::new(
            deadline.clone().with_parent(self.resources.deadline.take()),
        ));
        self.finalize(run, |events| {
            session::deliver(deadline, events, event_sink).map_err(Error::Output)
        })
        .map_err(BoundaryError::from_error)
    }
}
