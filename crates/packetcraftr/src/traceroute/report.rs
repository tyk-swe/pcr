// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::execution::Shared;
use crate::probe::{ProbeStatus, Transport, index_or_push};
use crate::{BoundaryError, Sink, Stats};

use super::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseKind {
    Intermediate,
    DestinationReached,
    Unreachable,
}

impl ResponseKind {
    /// The name the CLI prints, identical to the serialized one.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intermediate => "intermediate",
            Self::DestinationReached => "destination_reached",
            Self::Unreachable => "unreachable",
        }
    }

    pub(in crate::traceroute) const fn rank(self) -> u8 {
        match self {
            Self::Intermediate => 1,
            Self::Unreachable => 2,
            Self::DestinationReached => 3,
        }
    }
}

impl std::fmt::Display for ResponseKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why a trace stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    DestinationReached,
    Unreachable,
    MaximumHops,
    Timeout,
}

impl Termination {
    /// The name the CLI prints, identical to the serialized one.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DestinationReached => "destination_reached",
            Self::Unreachable => "unreachable",
            Self::MaximumHops => "maximum_hops",
            Self::Timeout => "timeout",
        }
    }
}

impl std::fmt::Display for Termination {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct ProbeEvidence {
    pub sequence: u64,
    pub hop_limit: u8,
    pub attempt: u32,
    pub destination: IpAddr,
    pub strategy: Transport,
    pub destination_port: Option<u16>,
    pub status: ProbeStatus,
    pub response_kind: Option<ResponseKind>,
    pub responder: Option<IpAddr>,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<Frame>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct Hop {
    pub hop_limit: u8,
    pub probes: Vec<ProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct UndecodedEvidence {
    pub hop_limit: u8,
    pub frame: Frame,
}

/// Every event one trace published, joined with its terminal [`Report`]:
/// each hop's probes in publication order.
#[derive(Clone, Debug)]
pub struct Aggregate {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: Transport,
    pub destination_port: Option<u16>,
    pub hops: Vec<Hop>,
    pub undecoded: Vec<UndecodedEvidence>,
    pub termination: Termination,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

/// What a trace publishes while it runs. Each event is answered before a
/// later hop starts.
#[derive(Clone, Debug)]
pub enum Event {
    /// A probe's final outcome.
    Probe {
        target: Arc<str>,
        probe: ProbeEvidence,
    },
    Undecoded(UndecodedEvidence),
    Diagnostic(Diagnostic),
}

/// The terminal result of one trace, returned after every probe event was
/// published. Diagnostics are not repeated here: each one already reached the
/// caller as [`Event::Diagnostic`] when it was raised.
#[derive(Clone, Debug)]
pub struct Report {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: Transport,
    pub destination_port: Option<u16>,
    pub termination: Termination,
    pub stats: Stats,
}

/// A sink that keeps every published probe outcome, undecoded frame, and
/// diagnostic. Pass a clone to [`Client::traceroute`](crate::Client::traceroute)
/// and [`finish`](Self::finish) the one kept with the report the trace
/// returns.
#[derive(Clone, Default)]
pub struct Collector(Shared<Collected>);

#[derive(Default)]
struct Collected {
    hops: Vec<Hop>,
    hop_indices: HashMap<u8, usize>,
    probes: u64,
    undecoded: Vec<UndecodedEvidence>,
    diagnostics: Vec<Diagnostic>,
}

impl Sink<Event> for Collector {
    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.update(|collected| collected.observe(event));
        Ok(())
    }
}

impl Collected {
    fn observe(&mut self, event: Event) {
        match event {
            Event::Probe { target: _, probe } => {
                self.probes = self.probes.saturating_add(1);
                let hop = index_or_push(
                    &mut self.hops,
                    &mut self.hop_indices,
                    probe.hop_limit,
                    || Hop {
                        hop_limit: probe.hop_limit,
                        probes: Vec::new(),
                    },
                );
                hop.probes.push(probe);
            }
            Event::Undecoded(evidence) => self.undecoded.push(evidence),
            Event::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
        }
    }
}

impl Collector {
    /// Joins the collected events with the trace's terminal `report`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncoherentEvents`] when the collected probe outcomes
    /// are not the ones the report counts.
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let Collected {
            hops,
            probes,
            undecoded,
            diagnostics,
            ..
        } = self.0.take();
        if probes != report.stats.packets_attempted {
            return Err(Error::IncoherentEvents {
                message: format!(
                    "{probes} probe outcome(s) collected for {} attempted probe(s)",
                    report.stats.packets_attempted
                ),
            });
        }
        Ok(Aggregate {
            target: report.target,
            resolved_addresses: report.resolved_addresses,
            destination: report.destination,
            strategy: report.strategy,
            destination_port: report.destination_port,
            hops,
            undecoded,
            termination: report.termination,
            diagnostics,
            stats: report.stats,
        })
    }
}
