// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;

use super::request::{Reuse, Strategy};
use super::selection::Observed;
use crate::execution::Shared;
use crate::probe::index_or_push;
use crate::target::ResolvedZone;
use crate::traceroute::{Error, Hop, ProbeEvidence, Termination};
use crate::{Sink, Stats};

/// Why a selected host was not traced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotTraced {
    /// No scan observation covers the host and the request names no strategy.
    NoResponsiveProbe,
    /// The host is a scoped link-local address, which tracing does not support.
    ScopedTarget,
}

impl NotTraced {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoResponsiveProbe => "no_responsive_probe",
            Self::ScopedTarget => "scoped_target",
        }
    }
}

impl std::fmt::Display for NotTraced {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How a host's trace ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// A probe reached the destination or drew an unreachable.
    Complete,
    /// The hop bounds ran out first.
    Incomplete,
    NotTraced(NotTraced),
}

/// What a host's probe choice rests on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Basis {
    /// The scan observation the probe was chosen from.
    Observed(Observed),
    /// The request's fallback strategy.
    Requested,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub strategy: Strategy,
    pub basis: Basis,
}

/// A hop copied from an earlier host's trace in the same operation instead of
/// being probed for this host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReusedHop {
    pub hop_limit: u8,
    /// The host whose trace observed the hop.
    pub source: IpAddr,
    /// The source trace's sequences of the probes that observed the hop.
    pub probes: Vec<u64>,
    /// Distinct responders in sequence order.
    pub responders: Vec<IpAddr>,
    /// The latest capture time among the source replies.
    pub observed_at: Option<SystemTime>,
    /// Time from the source batch being planned to this reuse.
    pub age: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub address: IpAddr,
    pub scope: Option<ResolvedZone>,
    pub state: State,
    pub selection: Option<Selection>,
    pub termination: Option<Termination>,
    /// Sequences of the probes sent for this host, in send order.
    pub probes: Vec<u64>,
    /// Hops copied from earlier hosts, ascending by hop limit.
    pub reused: Vec<ReusedHop>,
}

/// A frame no probe of its hop batch claimed.
#[derive(Clone, Debug)]
pub struct UndecodedEvidence {
    pub destination: IpAddr,
    pub hop_limit: u8,
    pub frame: Frame,
}

#[derive(Clone, Debug)]
pub enum Event {
    Probe(ProbeEvidence),
    Undecoded(UndecodedEvidence),
    Diagnostic(Diagnostic),
    /// Published after the host's last probe and before the next host's first.
    Host(Host),
}

/// Diagnostics are not repeated here: each one already reached the caller as
/// [`Event::Diagnostic`] when it was raised.
#[derive(Clone, Debug)]
pub struct Report {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    /// In selection order.
    pub hosts: Vec<Host>,
    pub reuse: Option<Reuse>,
    pub retained_evidence_bytes: usize,
    pub stats: Stats,
}

#[derive(Clone, Debug)]
pub struct HostTrace {
    pub host: Host,
    /// Freshly probed hops only, ascending by hop limit.
    pub hops: Vec<Hop>,
}

#[derive(Clone, Debug)]
pub struct Aggregate {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub hosts: Vec<HostTrace>,
    pub undecoded: Vec<UndecodedEvidence>,
    pub diagnostics: Vec<Diagnostic>,
    pub reuse: Option<Reuse>,
    pub retained_evidence_bytes: usize,
    pub stats: Stats,
}

#[derive(Clone, Default)]
pub struct Collector(Shared<Collected>);

#[derive(Default)]
struct Collected {
    probes: u64,
    hops: HashMap<IpAddr, Hops>,
    hosts: Vec<Host>,
    undecoded: Vec<UndecodedEvidence>,
    diagnostics: Vec<Diagnostic>,
}

#[derive(Default)]
struct Hops {
    hops: Vec<Hop>,
    indices: HashMap<u8, usize>,
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
            Event::Probe(probe) => {
                self.probes = self.probes.saturating_add(1);
                let hops = self.hops.entry(probe.destination).or_default();
                let hop_limit = probe.hop_limit;
                index_or_push(&mut hops.hops, &mut hops.indices, hop_limit, || Hop {
                    hop_limit,
                    probes: Vec::new(),
                })
                .probes
                .push(probe);
            }
            Event::Undecoded(evidence) => self.undecoded.push(evidence),
            Event::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
            Event::Host(host) => self.hosts.push(host),
        }
    }
}

impl Collector {
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let Collected {
            probes,
            mut hops,
            hosts,
            undecoded,
            diagnostics,
        } = self.0.take();
        if probes != report.stats.packets_attempted {
            return Err(Error::IncoherentEvents {
                message: format!(
                    "{probes} probe outcome(s) collected for {} attempted probe(s)",
                    report.stats.packets_attempted
                ),
            });
        }
        if hosts != report.hosts {
            return Err(Error::IncoherentEvents {
                message: format!(
                    "{} host record(s) collected disagree with the {} reported",
                    hosts.len(),
                    report.hosts.len()
                ),
            });
        }
        let traces = hosts
            .into_iter()
            .map(|host| {
                let mut hops = hops.remove(&host.address).unwrap_or_default().hops;
                hops.sort_by_key(|hop| hop.hop_limit);
                HostTrace { host, hops }
            })
            .collect();
        Ok(Aggregate {
            target: report.target,
            resolved_addresses: report.resolved_addresses,
            hosts: traces,
            undecoded,
            diagnostics,
            reuse: report.reuse,
            retained_evidence_bytes: report.retained_evidence_bytes,
            stats: report.stats,
        })
    }
}
