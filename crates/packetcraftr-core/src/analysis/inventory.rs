// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::analysis::pipeline::FrameRecord;
use crate::analysis::{StreamTransport, Summary as RunSummary};
use crate::packet::MacAddress;
use crate::protocol::identity;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedPort {
    pub transport: StreamTransport,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub address: IpAddr,
    pub mac_addresses: Vec<MacAddress>,
    pub protocols: Vec<String>,
    pub observed_ports: Vec<ObservedPort>,
    pub frames_sent: u64,
    pub frames_received: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolCount {
    pub protocol: String,
    pub frames: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub frames_read: u64,
    pub hosts: Vec<Host>,
    pub protocols: Vec<ProtocolCount>,
}

#[derive(Default)]
struct HostState {
    mac_addresses: BTreeSet<[u8; 6]>,
    protocols: BTreeSet<String>,
    observed_ports: BTreeSet<(StreamTransport, u16)>,
    frames_sent: u64,
    frames_received: u64,
}

#[derive(Default)]
pub struct Collector {
    hosts: BTreeMap<IpAddr, HostState>,
    protocols: BTreeMap<String, u64>,
}

impl Collector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, record: &FrameRecord<'_>) {
        let mut seen: Vec<&str> = Vec::new();
        for layer in record.decoded.packet.iter() {
            let name = layer.protocol_id().as_str();
            if !seen.contains(&name) {
                seen.push(name);
            }
        }
        for name in &seen {
            *self.protocols.entry((*name).to_owned()).or_default() += 1;
        }

        let Some((source, destination)) = innermost_network(record) else {
            return;
        };
        for address in [source, destination] {
            let host = self.hosts.entry(address).or_default();
            for name in &seen {
                host.protocols.insert((*name).to_owned());
            }
        }
        self.hosts.entry(source).or_default().frames_sent += 1;
        self.hosts.entry(destination).or_default().frames_received += 1;

        if let Some((source_mac, _)) = record
            .decoded
            .packet
            .iter()
            .find_map(identity::link_addresses)
        {
            self.hosts
                .entry(source)
                .or_default()
                .mac_addresses
                .insert(source_mac);
        }

        for (transport, conversation) in [
            (
                StreamTransport::Tcp,
                record.tcp.and_then(|view| view.conversation),
            ),
            (
                StreamTransport::Udp,
                record.udp.and_then(|view| view.conversation),
            ),
        ] {
            if let Some(stream) = conversation {
                let flow = &stream.flow.flow;
                self.hosts
                    .entry(flow.source)
                    .or_default()
                    .observed_ports
                    .insert((transport, flow.source_port));
                self.hosts
                    .entry(flow.destination)
                    .or_default()
                    .observed_ports
                    .insert((transport, flow.destination_port));
            }
        }
    }

    #[must_use]
    pub fn finish(self, summary: &RunSummary) -> Report {
        Report {
            frames_read: summary.frames_read,
            hosts: self
                .hosts
                .into_iter()
                .map(|(address, state)| Host {
                    address,
                    mac_addresses: state.mac_addresses.into_iter().map(MacAddress).collect(),
                    protocols: state.protocols.into_iter().collect(),
                    observed_ports: state
                        .observed_ports
                        .into_iter()
                        .map(|(transport, port)| ObservedPort { transport, port })
                        .collect(),
                    frames_sent: state.frames_sent,
                    frames_received: state.frames_received,
                })
                .collect(),
            protocols: self
                .protocols
                .into_iter()
                .map(|(protocol, frames)| ProtocolCount { protocol, frames })
                .collect(),
        }
    }
}

fn innermost_network(record: &FrameRecord<'_>) -> Option<(IpAddr, IpAddr)> {
    let mut network = None;
    for layer in record.decoded.packet.iter() {
        if let Some(endpoints) = identity::network_endpoints(layer) {
            network = Some(endpoints);
        }
    }
    network
}
