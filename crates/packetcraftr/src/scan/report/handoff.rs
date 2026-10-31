// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan results handed to the workflows that follow a scan: tracing the
//! responsive hosts and identifying the services at open endpoints.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};

use super::{Aggregate, Endpoint};
use crate::identify;
use crate::probe::{self, Reply, Transport};
use crate::scan::State;
use crate::traceroute::hosts::Observed;

impl Aggregate {
    /// The probe each responsive host's scan results support tracing with.
    ///
    /// Only a reply from the host itself qualifies, so a router's ICMP error never
    /// does. A TCP SYN/ACK is preferred over a TCP reset, which is preferred over
    /// an ICMP echo reply; ties go to the lowest scan sequence. UDP replies are not
    /// selected: a UDP trace changes the destination port on every probe, so one
    /// observed port would not cover the probes sent. The result is ordered by the
    /// chosen probe's sequence.
    #[must_use]
    pub fn trace_observations(&self) -> Vec<Observed> {
        let mut best: HashMap<IpAddr, (u8, Observed)> = HashMap::new();
        let probes = self
            .discovery
            .iter()
            .chain(self.endpoints.iter().flat_map(|endpoint| &endpoint.probes));
        for probe in probes {
            let Some(reply) = probe.reply else {
                continue;
            };
            if probe.status != probe::Status::Response
                || probe.scope.is_some()
                || probe.responder != Some(probe.address)
            {
                continue;
            }
            let (rank, transport, destination_port) = match (reply, probe.endpoint.transport()) {
                (Reply::TcpSynAck, Transport::Tcp) => (3, Transport::Tcp, probe.endpoint.port()),
                (Reply::TcpReset, Transport::Tcp) => (2, Transport::Tcp, probe.endpoint.port()),
                (Reply::IcmpEchoReply, Transport::Icmp) => (1, Transport::Icmp, None),
                _ => continue,
            };
            if transport == Transport::Tcp && probe.endpoint.port().is_none_or(|port| port == 0) {
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
}

impl Endpoint {
    /// The service-identification endpoint for an endpoint inferred open, or
    /// for a UDP endpoint inferred open-or-filtered. Selection itself sends
    /// nothing; the caller must invoke identify.
    pub fn identify_endpoint(&self) -> Option<identify::Endpoint> {
        let state = self.inference.as_ref()?.state?;
        let transport = match self.endpoint.transport() {
            probe::Transport::Tcp if state == State::Open => identify::Transport::Tcp,
            probe::Transport::Udp if matches!(state, State::Open | State::OpenOrFiltered) => {
                identify::Transport::Udp
            }
            _ => return None,
        };
        let port = self.endpoint.port()?;
        let address = match self.address {
            IpAddr::V4(address) => SocketAddr::new(address.into(), port),
            IpAddr::V6(address) => SocketAddr::V6(SocketAddrV6::new(
                address,
                port,
                0,
                self.scope.as_ref().map_or(0, |scope| scope.interface.index),
            )),
        };
        Some(identify::Endpoint { address, transport })
    }
}
