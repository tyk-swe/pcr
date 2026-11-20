// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::analysis::pipeline::FrameRecord;
use crate::analysis::{StreamTransport, Summary as RunSummary};
use crate::packet::{MacAddress, Packet};
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
        self.observe_frame(&record.decoded.packet);

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
                if usable_host(flow.source) {
                    self.hosts
                        .entry(flow.source)
                        .or_default()
                        .observed_ports
                        .insert((transport, flow.source_port));
                }
                if usable_host(flow.destination) {
                    self.hosts
                        .entry(flow.destination)
                        .or_default()
                        .observed_ports
                        .insert((transport, flow.destination_port));
                }
            }
        }
    }

    fn observe_frame(&mut self, packet: &Packet) {
        let mut sent = BTreeSet::new();
        let mut received = BTreeSet::new();
        let mut frame_protocols = BTreeSet::new();
        let mut network_protocols = BTreeSet::new();
        let mut endpoints = None;
        for layer in packet.iter() {
            let network = identity::network_endpoints(layer);
            let arp = identity::arp_message(layer);
            if (network.is_some() || arp.is_some() || identity::link_addresses(layer).is_some())
                && let Some(previous) = endpoints.take()
            {
                self.record_host_protocols(previous, &network_protocols);
                network_protocols.clear();
            }
            if let Some((source, destination)) = network {
                sent.insert(source);
                received.insert(destination);
                endpoints = Some((source, Some(destination)));
            } else if let Some(arp) = arp
                && !arp.sender_protocol.is_unspecified()
            {
                let sender = IpAddr::V4(arp.sender_protocol);
                self.hosts
                    .entry(sender)
                    .or_default()
                    .mac_addresses
                    .insert(arp.sender_hardware);
                sent.insert(sender);
                endpoints = Some((sender, None));
            }
            let name = layer.protocol_id().as_str();
            frame_protocols.insert(name);
            network_protocols.insert(name);
        }
        if let Some(endpoints) = endpoints {
            self.record_host_protocols(endpoints, &network_protocols);
        }
        for address in sent {
            self.hosts.entry(address).or_default().frames_sent += 1;
        }
        for address in received {
            self.hosts.entry(address).or_default().frames_received += 1;
        }
        for name in frame_protocols {
            *self.protocols.entry(name.to_owned()).or_default() += 1;
        }
    }

    fn record_host_protocols(
        &mut self,
        (source, destination): (IpAddr, Option<IpAddr>),
        protocols: &BTreeSet<&str>,
    ) {
        for address in std::iter::once(source).chain(destination) {
            self.hosts
                .entry(address)
                .or_default()
                .protocols
                .extend(protocols.iter().map(|name| (*name).to_owned()));
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

fn usable_host(address: IpAddr) -> bool {
    if address.is_unspecified() || address.is_multicast() {
        return false;
    }
    !matches!(address, IpAddr::V4(v4) if v4.is_broadcast())
}
