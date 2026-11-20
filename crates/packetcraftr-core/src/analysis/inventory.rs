// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;

use crate::analysis::pipeline::{self, FrameRecord};
use crate::analysis::{Error, Options, StreamTransport, Summary as RunSummary};
use crate::capture_file::Reader;
use crate::packet::MacAddress;
use crate::protocol::identity;
use crate::protocol::link::Arp;
use crate::registry::Registry;

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

/// Inventories untimed frames without using them for time-based reassembly.
/// When time bounds are set, untimed frames only count toward input totals.
pub fn run<R: Read>(
    reader: &mut Reader<R>,
    registry: Arc<Registry>,
    options: &Options<'_>,
) -> Result<Report, Error> {
    let mut collector = Collector::new();
    let summary = pipeline::run_observations(reader, registry, options, |record| {
        collector.observe_record(&record);
        Ok(())
    })?;
    Ok(collector.finish(&summary))
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
        self.observe_record(record);
    }

    fn observe_record<T>(&mut self, record: &FrameRecord<'_, T>) {
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

        if let Some(arp) = record.decoded.packet.get::<Arp>()
            && !arp.sender_protocol.is_unspecified()
        {
            let sender = IpAddr::V4(arp.sender_protocol);
            let host = self.hosts.entry(sender).or_default();
            host.mac_addresses.insert(arp.sender_hardware);
            host.frames_sent += 1;
            for name in &seen {
                host.protocols.insert((*name).to_owned());
            }
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

fn innermost_network<T>(record: &FrameRecord<'_, T>) -> Option<(IpAddr, IpAddr)> {
    let mut network = None;
    for layer in record.decoded.packet.iter() {
        if let Some(endpoints) = identity::network_endpoints(layer) {
            network = Some(endpoints);
        }
    }
    network
}
