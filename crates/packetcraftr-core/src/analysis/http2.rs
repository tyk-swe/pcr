// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Sourced cleartext HTTP/2 and h2c analysis over reassembled TCP.

mod budget;
mod buffer;
mod connection;
mod headers;
mod issue;
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
pub use issue::IssueCode;
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
use connection::ConnectionState;
use std::collections::{BTreeMap, BTreeSet};

use super::{
    FrameRecord, ScopedFlowKey, Summary as RunSummary,
    application::{self, TcpStreamFilter},
    scope::Definition,
    session::{self, CollectorNeeds},
};

type ConnectionKey = (u64, u64);

struct TransportFault {
    status: Status,
    code: IssueCode,
    detail: &'static str,
}

#[cfg(test)]
thread_local! {
    static FAILURE_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static REPLACEMENT_FLOWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

struct Resources {
    app_limits: application::Limits,
    limits: Limits,
    budget: Budget,
}

impl Resources {
    fn context<'a>(
        &'a mut self,
        deadline: Option<&'a Deadline>,
        out: &'a mut Vec<Event>,
    ) -> Context<'a> {
        Context {
            limits: &self.limits,
            app: &self.app_limits,
            deadline,
            budget: &mut self.budget,
            out,
        }
    }
}

#[derive(Default)]
struct FlowRegistry {
    flow_to_connection: BTreeMap<ScopedFlowKey, ConnectionKey>,
    connection_to_flows: BTreeMap<ConnectionKey, BTreeSet<ScopedFlowKey>>,
}

impl FlowRegistry {
    fn get(&self, flow: &ScopedFlowKey) -> Option<ConnectionKey> {
        self.flow_to_connection.get(flow).copied()
    }

    fn get_either(&self, flow: &ScopedFlowKey) -> Option<ConnectionKey> {
        self.get(flow).or_else(|| self.get(&flow.reverse()))
    }

    fn distinct_pair(&self, flow: &ScopedFlowKey) -> [Option<ConnectionKey>; 2] {
        let mut keys = [flow, &flow.reverse()].map(|candidate| {
            #[cfg(test)]
            FAILURE_LOOKUPS.with(|count| count.set(count.get() + 1));
            self.get(candidate)
        });
        keys.sort_unstable();
        let [first, second] = keys;
        [first, second.filter(|key| Some(*key) != first)]
    }

    fn associate(&mut self, flow: ScopedFlowKey, key: ConnectionKey) {
        if let Some(old) = self.flow_to_connection.insert(flow.clone(), key)
            && old != key
            && let Some(flows) = self.connection_to_flows.get_mut(&old)
        {
            flows.remove(&flow);
            if flows.is_empty() {
                self.connection_to_flows.remove(&old);
            }
        }
        self.connection_to_flows
            .entry(key)
            .or_default()
            .insert(flow);
    }

    fn forget(&mut self, key: ConnectionKey) {
        let Some(flows) = self.connection_to_flows.remove(&key) else {
            return;
        };
        for flow in flows {
            #[cfg(test)]
            REPLACEMENT_FLOWS.with(|count| count.set(count.get() + 1));
            if self.flow_to_connection.get(&flow) == Some(&key) {
                self.flow_to_connection.remove(&flow);
            }
        }
    }

    fn clear(&mut self) {
        self.flow_to_connection.clear();
        self.connection_to_flows.clear();
    }
}

pub struct Collector {
    resources: Resources,
    tcp: TcpStreamFilter,
    // Boxed to keep B-tree nodes small; connection state is large.
    connections: BTreeMap<ConnectionKey, Box<ConnectionState>>,
    flows: FlowRegistry,
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
                budget: Budget::new(application),
            },
            tcp: TcpStreamFilter::new(ports, application),
            connections: BTreeMap::new(),
            flows: FlowRegistry::default(),
            failed: false,
        })
    }

    pub fn scopes(&self) -> impl Iterator<Item = &Definition> {
        self.tcp.scopes()
    }

    pub fn observe(
        &mut self,
        record: &FrameRecord<'_>,
        deadline: &Deadline,
    ) -> Result<Vec<Event>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let mut out = Vec::new();
        if let Err(error) = self.observe_into(record, deadline, &mut out) {
            self.failed = true;
            self.connections.clear();
            self.flows.clear();
            return Err(error);
        }
        Ok(out)
    }

    fn observe_into(
        &mut self,
        record: &FrameRecord<'_>,
        deadline: &Deadline,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        deadline.enforce()?;
        for event in self.tcp.observe(record)? {
            self.dispatch(event, record.number, Some(deadline), out)?;
        }
        Ok(())
    }

    fn dispatch(
        &mut self,
        event: application::Event,
        number: u64,
        deadline: Option<&Deadline>,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        match event {
            application::Event::Data(delivery) => {
                let key = (delivery.stream, delivery.generation);
                if let Some(old) = self.flows.get(&delivery.flow)
                    && old != key
                    && let Some(mut conn) = self.connections.remove(&old)
                {
                    self.flows.forget(old);
                    conn.set_frame_number(number);
                    if !conn.is_inactive() {
                        conn.terminate(
                            &delivery.flow,
                            Status::Evicted,
                            IssueCode::GenerationReplaced,
                            "the TCP tuple was reused for a newer connection",
                            &mut self.resources.context(deadline, out),
                        )?;
                    }
                    conn.finish(&mut self.resources.context(deadline, out))?;
                }
                self.flows.associate(delivery.flow.clone(), key);
                let conn = self.connections.entry(key).or_insert_with(|| {
                    Box::new(ConnectionState::new(
                        delivery.stream,
                        delivery.generation,
                        delivery.flow.clone(),
                    ))
                });
                conn.data(
                    &delivery,
                    number,
                    &mut self.resources.context(deadline, out),
                )
            }
            application::Event::Gap { flow, .. } => self.fail_flow(
                &flow,
                number,
                TransportFault {
                    status: Status::Gap,
                    code: IssueCode::TcpGap,
                    detail: "a TCP sequence gap invalidated the byte stream",
                },
                deadline,
                out,
            ),
            application::Event::Conflict { flow, .. } => self.fail_flow(
                &flow,
                number,
                TransportFault {
                    status: Status::Conflict,
                    code: IssueCode::TcpConflict,
                    detail: "conflicting TCP retransmissions invalidated the byte stream",
                },
                deadline,
                out,
            ),
            application::Event::Evicted { flow, .. } => self.fail_flow(
                &flow,
                number,
                TransportFault {
                    status: Status::Evicted,
                    code: IssueCode::TcpEvicted,
                    detail: "reassembly state was evicted before the stream completed",
                },
                deadline,
                out,
            ),
            application::Event::Closed { flow, reset, .. } => {
                let Some(conn) = self
                    .flows
                    .get_either(&flow)
                    .and_then(|key| self.connections.get_mut(&key))
                    .filter(|conn| conn.has_flow(&flow) || conn.has_flow(&flow.reverse()))
                else {
                    return Ok(());
                };
                conn.set_frame_number(number);
                conn.close(&flow, reset, &mut self.resources.context(deadline, out))
            }
        }
    }

    fn fail_flow(
        &mut self,
        flow: &ScopedFlowKey,
        number: u64,
        fault: TransportFault,
        deadline: Option<&Deadline>,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        for key in self.flows.distinct_pair(flow).into_iter().flatten() {
            if let Some(conn) = self.connections.get_mut(&key) {
                conn.set_frame_number(number);
                conn.terminate(
                    flow,
                    fault.status,
                    fault.code,
                    fault.detail,
                    &mut self.resources.context(deadline, out),
                )?;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn associate_flow(&mut self, flow: ScopedFlowKey, key: ConnectionKey) {
        self.flows.associate(flow, key);
    }

    #[cfg(test)]
    fn forget_connection_flows(&mut self, key: ConnectionKey) {
        self.flows.forget(key);
    }

    pub fn finish(self, run: &RunSummary) -> Result<(Vec<Event>, Summary), Error> {
        let mut out = Vec::new();
        let summary = self.finalize(run, None, |events| {
            out.extend(events);
            Ok(())
        })?;
        Ok((out, summary))
    }

    fn finalize(
        mut self,
        run: &RunSummary,
        deadline: Option<&Deadline>,
        mut emit: impl FnMut(Vec<Event>) -> Result<(), Error>,
    ) -> Result<Summary, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if let Some(deadline) = deadline {
            deadline.enforce()?;
        }
        for event in self
            .tcp
            .trailing(&run.trailing_tcp_events, run.frames_read)?
        {
            if let Some(deadline) = deadline {
                deadline.enforce()?;
            }
            let mut out = Vec::new();
            if !matches!(event, application::Event::Evicted { .. }) {
                self.dispatch(event, run.frames_read, deadline, &mut out)?;
            }
            emit(out)?;
        }
        for mut conn in std::mem::take(&mut self.connections).into_values() {
            if let Some(deadline) = deadline {
                deadline.enforce()?;
            }
            let mut out = Vec::new();
            conn.set_frame_number(run.frames_read);
            conn.finish(&mut self.resources.context(deadline, &mut out))?;
            emit(out)?;
        }
        if let Some(deadline) = deadline {
            deadline.enforce()?;
        }
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

    fn observe(
        &mut self,
        record: &FrameRecord<'_>,
        deadline: &Deadline,
    ) -> Result<Vec<Event>, BoundaryError> {
        Self::observe(self, record, deadline).map_err(BoundaryError::from_error)
    }

    fn finish(
        self,
        run: &RunSummary,
        deadline: &Deadline,
        event_sink: &mut dyn FnMut(Event) -> Result<(), BoundaryError>,
    ) -> Result<Summary, BoundaryError> {
        self.finalize(run, Some(deadline), |events| {
            session::deliver(deadline, events, event_sink).map_err(Error::Output)
        })
        .map_err(BoundaryError::from_error)
    }
}
