// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::registry::Registry;

use super::report::{Event, Host, ReusedHop, Selection, State, UndecodedEvidence};
use super::request::Request;
use super::reuse::{Cache, Intermediate};
use crate::evidence::SentPacket;
use crate::probe::runner::{BatchEvidence, Classifier, Outcome as ProbeOutcome};
use crate::probe::{Batch, ProbeEndpoint, ProbeStatus, Transport, enforce_deadline};
use crate::target::ResolvedZone;
use crate::traceroute::error::Probes;
use crate::traceroute::evidence::{fold_termination, probe_evidence};
use crate::traceroute::plan::packet::sent_probe_matches;
use crate::traceroute::{
    CorrelatedResponse, Error, Probe, ResponseKind, Termination, classify_response,
};

#[derive(Clone, Debug)]
pub(super) struct Outcome {
    sequence: u64,
    status: ProbeStatus,
    kind: Option<ResponseKind>,
    responder: Option<IpAddr>,
    received_at: Option<SystemTime>,
}

impl Outcome {
    fn ends_trace(&self) -> bool {
        matches!(
            self.kind,
            Some(ResponseKind::DestinationReached | ResponseKind::Unreachable)
        )
    }
}

/// Classifies like standalone traceroute but never ends the operation, and
/// records each batch's outcomes for the planner.
pub(super) struct HostsClassifier<'a> {
    pub(super) registry: &'a Registry,
    pub(super) batch: Vec<Outcome>,
}

impl HostsClassifier<'_> {
    fn take_batch(&mut self) -> Vec<Outcome> {
        std::mem::take(&mut self.batch)
    }
}

impl Classifier for HostsClassifier<'_> {
    type Probe = Probe;
    type Observation = CorrelatedResponse;
    type Event = Event;

    fn sent_matches(&self, probe: &Probe, sent: &Packet) -> bool {
        sent_probe_matches(probe, sent)
    }

    fn classify(
        &self,
        probe: &Probe,
        sent: &SentPacket,
        response: &DecodedPacket,
    ) -> Option<CorrelatedResponse> {
        classify_response(
            self.registry,
            probe.target.transport(),
            &sent.built().packet,
            response,
        )
    }

    fn rank(&self, observation: &CorrelatedResponse) -> u8 {
        observation.kind.rank()
    }

    fn responder(&self, observation: &CorrelatedResponse) -> IpAddr {
        observation.responder
    }

    fn evidence(
        &mut self,
        probe: &Probe,
        sent: &SentPacket,
        outcome: ProbeOutcome<CorrelatedResponse>,
    ) -> Event {
        let evidence = probe_evidence(probe, sent, outcome);
        self.batch.push(Outcome {
            sequence: evidence.sequence,
            status: evidence.status,
            kind: evidence.response_kind,
            responder: evidence.responder,
            received_at: evidence.received_at,
        });
        Event::Probe(evidence)
    }

    fn undecoded(&self, probes: &[Probe], frame: Frame) -> Event {
        let first = probes
            .first()
            .expect("serial traceroute retains undecoded frames with their hop batch");
        Event::Undecoded(UndecodedEvidence {
            destination: first.address,
            hop_limit: first.hop_limit,
            frame,
        })
    }

    fn diagnostic(&self, diagnostic: Diagnostic) -> Event {
        Event::Diagnostic(diagnostic)
    }
}

pub(super) struct Slot {
    pub(super) address: IpAddr,
    pub(super) scope: Option<ResolvedZone>,
    pub(super) trace: Result<Selection, super::report::NotTraced>,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Start,
    Descend { hop_limit: u8 },
    Fill { source: usize, hop_limit: u8 },
    Upward { next: u16 },
}

struct Fresh {
    planned_at: Instant,
    outcomes: Vec<Outcome>,
}

struct Current {
    slot: usize,
    selection: Selection,
    mode: Mode,
    anchor: Option<u8>,
    fresh: BTreeMap<u8, Fresh>,
    probes: Vec<u64>,
    reused: Vec<ReusedHop>,
    sent: u64,
}

pub(super) struct Planner<'r> {
    request: &'r Request,
    slots: Vec<Slot>,
    next_slot: usize,
    current: Option<Current>,
    in_flight: Option<u8>,
    caches: Vec<Cache>,
    hosts: Vec<Host>,
    next_sequence: u64,
}

impl<'r> Planner<'r> {
    pub(super) fn new(request: &'r Request, slots: Vec<Slot>) -> Self {
        let max_age = request.reuse.map_or(Duration::ZERO, |reuse| reuse.max_age);
        Self {
            request,
            slots,
            next_slot: 0,
            current: None,
            in_flight: None,
            caches: (0..6).map(|_| Cache::new(max_age)).collect(),
            hosts: Vec::new(),
            next_sequence: 0,
        }
    }

    pub(super) fn into_hosts(self) -> Vec<Host> {
        self.hosts
    }

    /// Plans the next batch. `now` is sampled fresh at every loop, not once
    /// per call: publishing a host event may take real sink time, and the next
    /// host's anchor and reuse decisions must see it.
    pub(super) fn next<F>(
        &mut self,
        evidence: &mut BatchEvidence<HostsClassifier<'_>, F, Probes>,
        mut now: impl FnMut() -> Instant,
        deadline: &Deadline,
    ) -> Result<Option<Batch<Probe>>, Error>
    where
        F: FnMut(Event, &Deadline) -> Result<(), Error>,
    {
        if let Some(hop_limit) = self.in_flight.take() {
            let outcomes = evidence.classifier_mut().take_batch();
            if let Some(current) = &mut self.current {
                let cache = &self.caches[cache_index(
                    self.slots[current.slot].address,
                    current.selection.strategy.transport,
                )];
                current.observe(self.request, cache, hop_limit, outcomes, now());
            }
        }
        loop {
            enforce_deadline(&Probes, deadline)?;
            let now = now();
            if self.current.is_none() {
                let Some(slot) = self.slots.get(self.next_slot) else {
                    return Ok(None);
                };
                let index = self.next_slot;
                self.next_slot += 1;
                match &slot.trace {
                    Ok(selection) => {
                        self.current = Some(Current {
                            slot: index,
                            selection: selection.clone(),
                            mode: Mode::Start,
                            anchor: None,
                            fresh: BTreeMap::new(),
                            probes: Vec::new(),
                            reused: Vec::new(),
                            sent: 0,
                        });
                    }
                    Err(reason) => {
                        let host = Host {
                            address: slot.address,
                            scope: slot.scope.clone(),
                            state: State::NotTraced(*reason),
                            selection: None,
                            termination: None,
                            probes: Vec::new(),
                            reused: Vec::new(),
                        };
                        evidence.emit(Event::Host(host.clone()), deadline)?;
                        self.hosts.push(host);
                        continue;
                    }
                }
            }
            let current = self.current.as_mut().expect("a host is being traced");
            let address = self.slots[current.slot].address;
            let cache = &self.caches[cache_index(address, current.selection.strategy.transport)];
            match current.decide(self.request, cache, now) {
                Some(hop_limit) => {
                    let batch = current.batch(
                        self.request,
                        address,
                        hop_limit,
                        &mut self.next_sequence,
                        now,
                    )?;
                    self.in_flight = Some(hop_limit);
                    return Ok(Some(batch));
                }
                None => {
                    let current = self.current.take().expect("a host is being traced");
                    let host = self.finish(current);
                    evidence.emit(Event::Host(host.clone()), deadline)?;
                    self.hosts.push(host);
                }
            }
        }
    }

    fn finish(&mut self, current: Current) -> Host {
        let slot = &self.slots[current.slot];
        let termination = current
            .fresh
            .values()
            .flat_map(|fresh| &fresh.outcomes)
            .fold(Termination::Timeout, |termination, outcome| {
                fold_termination(termination, outcome.kind, outcome.status)
            });
        if self.request.reuse.is_some() {
            let cache =
                &mut self.caches[cache_index(slot.address, current.selection.strategy.transport)];
            for (hop_limit, fresh) in &current.fresh {
                let intermediates: Vec<_> = fresh
                    .outcomes
                    .iter()
                    .filter(|outcome| outcome.kind == Some(ResponseKind::Intermediate))
                    .filter_map(|outcome| {
                        Some(Intermediate {
                            sequence: outcome.sequence,
                            responder: outcome.responder?,
                            received_at: outcome.received_at,
                        })
                    })
                    .collect();
                if !intermediates.is_empty() {
                    cache.insert(
                        current.slot,
                        slot.address,
                        *hop_limit,
                        intermediates,
                        fresh.planned_at,
                    );
                }
            }
        }
        let mut reused = current.reused;
        reused.sort_by_key(|hop| hop.hop_limit);
        Host {
            address: slot.address,
            scope: slot.scope.clone(),
            state: match termination {
                Termination::DestinationReached | Termination::Unreachable => State::Complete,
                Termination::MaximumHops | Termination::Timeout => State::Incomplete,
            },
            selection: Some(current.selection),
            termination: Some(termination),
            probes: current.probes,
            reused,
        }
    }
}

/// Hops are reused only between hosts of one address family traced with one
/// transport, because paths can depend on both.
fn cache_index(address: IpAddr, transport: Transport) -> usize {
    let transport = match transport {
        Transport::Tcp => 0,
        Transport::Udp => 1,
        Transport::Icmp => 2,
    };
    usize::from(address.is_ipv6()) * 3 + transport
}

impl Current {
    fn below(&self, request: &Request, hop_limit: u8, then: impl Fn(u8) -> Mode) -> Mode {
        match hop_limit
            .checked_sub(1)
            .filter(|lower| *lower >= request.first_hop)
        {
            Some(lower) => then(lower),
            None => Mode::Upward {
                next: self
                    .anchor
                    .map_or(u16::from(request.first_hop), |anchor| u16::from(anchor) + 1),
            },
        }
    }

    fn ended(&self) -> bool {
        self.fresh
            .values()
            .flat_map(|fresh| &fresh.outcomes)
            .any(Outcome::ends_trace)
    }

    /// The hop limit to probe next, or `None` when the host is done. Hops a
    /// fresh cache entry covers are recorded here without a probe.
    fn decide(&mut self, request: &Request, cache: &Cache, now: Instant) -> Option<u8> {
        loop {
            match self.mode {
                Mode::Start => {
                    self.anchor = cache.anchor(now);
                    self.mode = match self.anchor {
                        Some(hop_limit) => Mode::Descend { hop_limit },
                        None => Mode::Upward {
                            next: u16::from(request.first_hop),
                        },
                    };
                }
                Mode::Descend { hop_limit } => return Some(hop_limit),
                Mode::Fill { source, hop_limit } => match cache.reuse(source, hop_limit, now) {
                    Some(hop) => {
                        self.reused.push(hop);
                        self.mode = self.below(request, hop_limit, |lower| Mode::Fill {
                            source,
                            hop_limit: lower,
                        });
                    }
                    None => return Some(hop_limit),
                },
                Mode::Upward { next } => {
                    return match u8::try_from(next) {
                        Ok(hop_limit) if hop_limit <= request.max_hops && !self.ended() => {
                            Some(hop_limit)
                        }
                        _ => None,
                    };
                }
            }
        }
    }

    fn observe(
        &mut self,
        request: &Request,
        cache: &Cache,
        hop_limit: u8,
        outcomes: Vec<Outcome>,
        now: Instant,
    ) {
        let responders: Vec<IpAddr> = outcomes
            .iter()
            .filter(|outcome| outcome.kind == Some(ResponseKind::Intermediate))
            .filter_map(|outcome| outcome.responder)
            .collect();
        if let Some(fresh) = self.fresh.get_mut(&hop_limit) {
            fresh.outcomes = outcomes;
        }
        self.mode = match self.mode {
            Mode::Descend { .. } => match cache.matching(hop_limit, &responders, now) {
                Some(source) => self.below(request, hop_limit, |lower| Mode::Fill {
                    source,
                    hop_limit: lower,
                }),
                None => self.below(request, hop_limit, |lower| Mode::Descend {
                    hop_limit: lower,
                }),
            },
            Mode::Fill { source, .. } => self.below(request, hop_limit, |lower| Mode::Fill {
                source,
                hop_limit: lower,
            }),
            Mode::Upward { next } => Mode::Upward { next: next + 1 },
            Mode::Start => Mode::Start,
        };
    }

    fn batch(
        &mut self,
        request: &Request,
        address: IpAddr,
        hop_limit: u8,
        next_sequence: &mut u64,
        now: Instant,
    ) -> Result<Batch<Probe>, Error> {
        let strategy = self.selection.strategy;
        let source_port = match strategy.transport {
            Transport::Icmp => 0,
            Transport::Udp | Transport::Tcp => request
                .source_port
                .unwrap_or(crate::traceroute::SOURCE_PORT),
        };
        let first_sequence = *next_sequence;
        let mut probes = Vec::new();
        for attempt in 1..=request.probes_per_hop {
            let target = match (strategy.transport, strategy.destination_port) {
                (Transport::Udp, Some(base)) => u16::try_from(self.sent)
                    .ok()
                    .and_then(|offset| base.checked_add(offset))
                    .map(|port| ProbeEndpoint::Udp { port }),
                (Transport::Tcp, Some(port)) => Some(ProbeEndpoint::Tcp { port }),
                (Transport::Icmp, None) => Some(ProbeEndpoint::Icmp),
                _ => None,
            }
            .ok_or_else(|| Error::InvalidPort {
                message: format!(
                    "{} probe {} of {address} has no valid destination port",
                    strategy.transport, self.sent
                ),
            })?;
            probes.push(Probe {
                sequence: *next_sequence,
                address,
                target,
                hop_limit,
                attempt,
                source_port,
                payload_size: request.payload_size,
                dont_fragment: request.dont_fragment,
                dscp: request.dscp,
            });
            self.probes.push(*next_sequence);
            *next_sequence = next_sequence
                .checked_add(1)
                .ok_or_else(|| super::request::overflow("probes"))?;
            self.sent += 1;
        }
        self.fresh.insert(
            hop_limit,
            Fresh {
                planned_at: now,
                outcomes: Vec::new(),
            },
        );
        Ok(Batch {
            probes,
            timeout: request.timeout,
            permit: crate::evidence::ExecutionPermit::new(),
            sequence: first_sequence,
        })
    }
}
