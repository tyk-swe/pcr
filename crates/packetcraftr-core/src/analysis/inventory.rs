// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;

use crate::analysis::pipeline::{self, FrameRecord};
use crate::analysis::{Error, Options, StreamTransport, Summary as RunSummary};
use crate::capture_file::Reader;
use crate::packet::{MacAddress, Packet};
use crate::protocol::identity;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPort {
    pub address: IpAddr,
    pub observed_port: ObservedPort,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacChange {
    pub address: IpAddr,
    pub before: Vec<MacAddress>,
    pub after: Vec<MacAddress>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub new_hosts: Vec<IpAddr>,
    pub gone_hosts: Vec<IpAddr>,
    pub new_ports: Vec<HostPort>,
    pub gone_ports: Vec<HostPort>,
    pub new_protocols: Vec<String>,
    pub gone_protocols: Vec<String>,
    pub mac_changes: Vec<MacChange>,
}

/// Compare passive inventories by observed identity only. A port is new
/// when the host/transport/port tuple was absent from the baseline, even
/// when its host already existed. This never claims a new host appeared at
/// the after time; it says only that the baseline capture did not show it.
#[must_use]
pub fn diff(before: &Report, after: &Report) -> Diff {
    let before_hosts: BTreeMap<IpAddr, &Host> = before
        .hosts
        .iter()
        .map(|host| (host.address, host))
        .collect();
    let after_hosts: BTreeMap<IpAddr, &Host> = after
        .hosts
        .iter()
        .map(|host| (host.address, host))
        .collect();
    let ports = |report: &Report| -> BTreeSet<(IpAddr, StreamTransport, u16)> {
        report
            .hosts
            .iter()
            .flat_map(|host| {
                host.observed_ports
                    .iter()
                    .map(move |port| (host.address, port.transport, port.port))
            })
            .collect()
    };
    let before_ports = ports(before);
    let after_ports = ports(after);
    let before_protocols: BTreeSet<&str> = before
        .protocols
        .iter()
        .map(|protocol| protocol.protocol.as_str())
        .collect();
    let after_protocols: BTreeSet<&str> = after
        .protocols
        .iter()
        .map(|protocol| protocol.protocol.as_str())
        .collect();
    let to_host_port = |(address, transport, port): (IpAddr, StreamTransport, u16)| HostPort {
        address,
        observed_port: ObservedPort { transport, port },
    };
    Diff {
        new_hosts: after_hosts
            .keys()
            .filter(|address| !before_hosts.contains_key(address))
            .copied()
            .collect(),
        gone_hosts: before_hosts
            .keys()
            .filter(|address| !after_hosts.contains_key(address))
            .copied()
            .collect(),
        new_ports: after_ports
            .difference(&before_ports)
            .copied()
            .map(to_host_port)
            .collect(),
        gone_ports: before_ports
            .difference(&after_ports)
            .copied()
            .map(to_host_port)
            .collect(),
        new_protocols: after_protocols
            .difference(&before_protocols)
            .map(|protocol| (*protocol).to_owned())
            .collect(),
        gone_protocols: before_protocols
            .difference(&after_protocols)
            .map(|protocol| (*protocol).to_owned())
            .collect(),
        mac_changes: before_hosts
            .iter()
            .filter_map(|(address, before_host)| {
                let after_host = after_hosts.get(address)?;
                (before_host.mac_addresses != after_host.mac_addresses).then(|| MacChange {
                    address: *address,
                    before: before_host.mac_addresses.clone(),
                    after: after_host.mac_addresses.clone(),
                })
            })
            .collect(),
    }
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
        collector.observe(&record);
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

    pub fn observe<T>(&mut self, record: &FrameRecord<'_, T>) {
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

#[cfg(test)]
mod diff_tests {
    use super::*;

    fn host(address: &str, macs: Vec<MacAddress>, ports: Vec<(StreamTransport, u16)>) -> Host {
        Host {
            address: address.parse().unwrap(),
            mac_addresses: macs,
            protocols: Vec::new(),
            observed_ports: ports
                .into_iter()
                .map(|(transport, port)| ObservedPort { transport, port })
                .collect(),
            frames_sent: 0,
            frames_received: 0,
        }
    }

    #[test]
    fn diff_reports_new_gone_and_changed_identities() {
        let before = Report {
            frames_read: 3,
            hosts: vec![
                host(
                    "10.0.0.1",
                    vec![MacAddress([1, 2, 3, 4, 5, 6])],
                    vec![(StreamTransport::Tcp, 80)],
                ),
                host("10.0.0.2", Vec::new(), Vec::new()),
            ],
            protocols: vec![ProtocolCount {
                protocol: "dns".to_owned(),
                frames: 1,
            }],
        };
        let after = Report {
            frames_read: 4,
            hosts: vec![
                host(
                    "10.0.0.1",
                    vec![MacAddress([6, 5, 4, 3, 2, 1])],
                    vec![(StreamTransport::Tcp, 443)],
                ),
                host("10.0.0.3", Vec::new(), Vec::new()),
            ],
            protocols: vec![ProtocolCount {
                protocol: "tls".to_owned(),
                frames: 1,
            }],
        };
        let diff = diff(&before, &after);
        assert_eq!(diff.new_hosts, vec!["10.0.0.3".parse::<IpAddr>().unwrap()]);
        assert_eq!(diff.gone_hosts, vec!["10.0.0.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(diff.new_ports[0].observed_port.port, 443);
        assert_eq!(diff.gone_ports[0].observed_port.port, 80);
        assert_eq!(diff.new_protocols, vec!["tls"]);
        assert_eq!(diff.gone_protocols, vec!["dns"]);
        assert_eq!(diff.mac_changes.len(), 1);
    }
}
