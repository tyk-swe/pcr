// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

use super::report::{Basis, NotTraced, Selection};
use super::request::{Request, Strategy};
use crate::probe::{ProbeStatus, Transport};
use crate::scan::{self, Reply, Stage};
use crate::target::SelectedAddress;

/// A probe a host answered during a scan, kept with the evidence that makes
/// it a sound choice for tracing that host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    pub address: IpAddr,
    pub transport: Transport,
    /// The TCP port that answered; `None` for ICMP.
    pub destination_port: Option<u16>,
    pub stage: Stage,
    /// The scan probe's sequence.
    pub sequence: u64,
    pub reply: Reply,
    /// When the scan captured the reply.
    pub observed_at: Option<SystemTime>,
}

/// The probe each responsive host's scan results support tracing with.
///
/// Only a reply from the host itself qualifies, so a router's ICMP error never
/// does. A TCP SYN/ACK is preferred over a TCP reset, which is preferred over
/// an ICMP echo reply; ties go to the lowest scan sequence. UDP replies are not
/// selected: a UDP trace changes the destination port on every probe, so one
/// observed port would not cover the probes sent. The result is ordered by the
/// chosen probe's sequence.
#[must_use]
pub fn observed(scan: &scan::Aggregate) -> Vec<Observed> {
    let mut best: HashMap<IpAddr, (u8, Observed)> = HashMap::new();
    let probes = scan
        .discovery
        .iter()
        .chain(scan.endpoints.iter().flat_map(|endpoint| &endpoint.probes));
    for probe in probes {
        let Some(reply) = probe.reply else {
            continue;
        };
        if probe.status != ProbeStatus::Response
            || probe.scope.is_some()
            || probe.responder != Some(probe.address)
        {
            continue;
        }
        let (rank, transport, destination_port) = match (reply, probe.transport) {
            (Reply::TcpSynAck, Transport::Tcp) => (3, Transport::Tcp, probe.port),
            (Reply::TcpReset, Transport::Tcp) => (2, Transport::Tcp, probe.port),
            (Reply::IcmpEchoReply, Transport::Icmp) => (1, Transport::Icmp, None),
            _ => continue,
        };
        if transport == Transport::Tcp && probe.port.is_none_or(|port| port == 0) {
            continue;
        }
        let candidate = Observed {
            address: probe.address,
            transport,
            destination_port,
            stage: probe.stage,
            sequence: probe.sequence,
            reply,
            observed_at: probe.received_at,
        };
        let better = best.get(&probe.address).is_none_or(|(held, current)| {
            rank > *held || (rank == *held && candidate.sequence < current.sequence)
        });
        if better {
            best.insert(probe.address, (rank, candidate));
        }
    }
    let mut chosen: Vec<_> = best.into_values().map(|(_, observed)| observed).collect();
    chosen.sort_by_key(|observed| observed.sequence);
    chosen
}

pub(super) enum Choice {
    Traced(Selection),
    NotTraced(NotTraced),
}

/// Picks the probe for one selected host: its observation first, then the
/// request's strategy; a host with neither is never guessed at.
pub(super) fn choose(
    request: &Request,
    observations: &HashMap<IpAddr, &Observed>,
    target: &SelectedAddress,
) -> Choice {
    if target.scope.is_some() {
        return Choice::NotTraced(NotTraced::ScopedTarget);
    }
    if let Some(observed) = observations.get(&target.address) {
        return Choice::Traced(Selection {
            strategy: Strategy {
                transport: observed.transport,
                destination_port: observed.destination_port,
            },
            basis: Basis::Observed((*observed).clone()),
        });
    }
    match request.strategy {
        Some(strategy) => Choice::Traced(Selection {
            strategy,
            basis: Basis::Requested,
        }),
        None => Choice::NotTraced(NotTraced::NoResponsiveProbe),
    }
}
