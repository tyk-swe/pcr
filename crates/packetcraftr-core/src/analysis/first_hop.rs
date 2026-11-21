// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! First-hop identity observations from decoded capture frames.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use crate::analysis::pipeline::{self, FrameRecord};
use crate::analysis::{Error, Options, Summary as RunSummary};
use crate::capture_file::Reader;
use crate::packet::{MacAddress, Packet};
use crate::protocol::BuiltinProtocol;
use crate::protocol::application::dhcp::{Dhcpv4, Dhcpv6, Value4, Value6};
use crate::protocol::identity::{self, EncapsulationIdentifier};
use crate::registry::Registry;

type ArpScope = Vec<(u16, u16)>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArpConflict {
    pub address: Ipv4Addr,
    pub broadcast_domain: Vec<EncapsulationIdentifier>,
    pub mac_addresses: Vec<MacAddress>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub frames_read: u64,
    pub arp_conflicts: Vec<ArpConflict>,
    pub dhcp_servers: Vec<String>,
    pub dhcpv6_servers: Vec<String>,
    pub router_advertisers: Vec<String>,
}

impl Report {
    #[must_use]
    pub fn has_multiple_dhcp_servers(&self) -> bool {
        self.dhcp_servers.len() > 1
    }

    #[must_use]
    pub fn has_multiple_dhcpv6_servers(&self) -> bool {
        self.dhcpv6_servers.len() > 1
    }

    #[must_use]
    pub fn has_multiple_router_advertisers(&self) -> bool {
        self.router_advertisers.len() > 1
    }
}

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
pub struct Collector {
    arp: BTreeMap<(Ipv4Addr, ArpScope), BTreeSet<[u8; 6]>>,
    dhcp_servers: BTreeSet<String>,
    dhcpv6_servers: BTreeSet<String>,
    router_advertisers: BTreeSet<String>,
}

impl Collector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe<T>(&mut self, record: &FrameRecord<'_, T>) {
        self.observe_packet(&record.decoded.packet);
    }

    fn observe_packet(&mut self, packet: &Packet) {
        self.observe_frame(packet);
        if let Some(dhcp) = packet.get::<Dhcpv4>()
            && dhcp.operation == 2
            && matches!(dhcp.message_type(), Some(2 | 5))
        {
            self.dhcp_servers.insert(dhcp_server_identity(packet, dhcp));
        }
        if let Some(dhcp) = packet.get::<Dhcpv6>() {
            self.observe_dhcpv6(packet, dhcp);
        }
    }

    fn observe_dhcpv6(&mut self, packet: &Packet, dhcp: &Dhcpv6) {
        if matches!(dhcp.message_type, 2 | 7) {
            self.dhcpv6_servers
                .insert(dhcpv6_server_identity(packet, dhcp));
        }
        for option in &dhcp.options {
            if let Value6::Relay(inner) = &option.value {
                self.observe_dhcpv6(packet, inner);
            }
        }
    }

    fn observe_frame(&mut self, packet: &Packet) {
        let mut link_source: Option<[u8; 6]> = None;
        let mut network_source: Option<IpAddr> = None;
        let mut broadcast_domain: ArpScope = Vec::new();
        for layer in packet.iter() {
            if let Some((source, _)) = identity::link_addresses(layer) {
                link_source = Some(source);
            }
            if let Some(tag) = identity::vlan_tag(layer) {
                broadcast_domain.push((tag.kind.ether_type(), tag.vlan_id));
            }
            if let Some((source, _)) = identity::network_endpoints(layer) {
                network_source = Some(source);
            }
            if let Some(arp) = identity::arp_message(layer)
                && !arp.sender_protocol.is_unspecified()
            {
                self.arp
                    .entry((arp.sender_protocol, broadcast_domain.clone()))
                    .or_default()
                    .insert(arp.sender_hardware);
            }
            if identity::icmp_message(layer).is_some_and(|message| {
                message.protocol == BuiltinProtocol::Icmpv6 && message.icmp_type == 134
            }) {
                let source = network_source
                    .map_or_else(|| "unknown-ip".to_owned(), |address| address.to_string());
                let mac =
                    link_source.map_or_else(|| "-".to_owned(), |mac| MacAddress(mac).to_string());
                self.router_advertisers.insert(format!("{source}@{mac}"));
            }
        }
    }

    #[must_use]
    pub fn finish(self, summary: &RunSummary) -> Report {
        Report {
            frames_read: summary.frames_read,
            arp_conflicts: self
                .arp
                .into_iter()
                .filter(|(_, macs)| macs.len() > 1)
                .map(|((address, broadcast_domain), macs)| ArpConflict {
                    address,
                    broadcast_domain: broadcast_domain
                        .into_iter()
                        .map(|(ether_type, vlan_id)| {
                            if ether_type == crate::packet::VlanKind::Ieee8021Ad.ether_type() {
                                EncapsulationIdentifier::Vlan8021ad { vlan_id }
                            } else {
                                EncapsulationIdentifier::Vlan { vlan_id }
                            }
                        })
                        .collect(),
                    mac_addresses: macs.into_iter().map(MacAddress).collect(),
                })
                .collect(),
            dhcp_servers: self.dhcp_servers.into_iter().collect(),
            dhcpv6_servers: self.dhcpv6_servers.into_iter().collect(),
            router_advertisers: self.router_advertisers.into_iter().collect(),
        }
    }
}

fn network_source(packet: &Packet) -> Option<IpAddr> {
    packet
        .iter()
        .rev()
        .find_map(identity::network_endpoints)
        .map(|(source, _)| source)
}

fn dhcp_server_identity(packet: &Packet, dhcp: &Dhcpv4) -> String {
    if let Some(address) = dhcp.all_options().find_map(|option| {
        if option.code != 54 {
            return None;
        }
        match option.value {
            Value4::Address(address) => Some(address),
            _ => None,
        }
    }) {
        return address.to_string();
    }
    if !dhcp.server_address.is_unspecified() {
        return dhcp.server_address.to_string();
    }
    network_source(packet).map_or_else(
        || "unknown-server".to_owned(),
        |address| address.to_string(),
    )
}

fn dhcpv6_server_identity(packet: &Packet, dhcp: &Dhcpv6) -> String {
    if let Some(duid) = dhcp.options.iter().find_map(|option| {
        if option.code != 2 {
            return None;
        }
        match &option.value {
            Value6::Identifier(duid) => Some(duid),
            _ => None,
        }
    }) {
        return format!(
            "duid:{}:{}",
            duid.kind,
            crate::field::hex::compact_hex(&duid.data)
        );
    }
    if dhcp.is_relay() && !dhcp.link_address.is_unspecified() {
        return dhcp.link_address.to_string();
    }
    network_source(packet).map_or_else(
        || "unknown-server".to_owned(),
        |address| address.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;
    use crate::protocol::application::dhcp::{Dhcpv6, Duid, Option4, Option6};
    use crate::protocol::link::{Arp, Vlan, Vlan8021ad};
    use crate::protocol::network::{Icmpv6, Ipv6};

    fn collect(packet: Packet, collector: &mut Collector) {
        collector.observe_packet(&packet);
    }

    #[test]
    fn collects_first_hop_identity_conflicts_and_multiple_servers() {
        let mut collector = Collector::new();
        for mac in [[1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1]] {
            let mut packet = Packet::default();
            packet.push(Arp {
                sender_hardware: mac,
                sender_protocol: "10.0.0.1".parse().unwrap(),
                ..Arp::default()
            });
            collect(packet, &mut collector);
        }
        for server in ["10.0.0.2", "10.0.0.3"] {
            let mut packet = Packet::default();
            let mut dhcp = Dhcpv4::default();
            dhcp.edit(|dhcp| {
                dhcp.operation = 2;
                dhcp.options = vec![
                    Option4::message_type(2),
                    Option4::server_identifier(server.parse().unwrap()),
                ];
            });
            packet.push(dhcp);
            collect(packet, &mut collector);
        }
        for source in ["fe80::1", "fe80::2"] {
            let mut packet = Packet::default();
            packet.push(Ipv6 {
                source: source.parse().unwrap(),
                ..Ipv6::default()
            });
            packet.push(Icmpv6 {
                icmp_type: 134,
                ..Icmpv6::default()
            });
            collect(packet, &mut collector);
        }

        let report = collector.finish(&RunSummary::default());
        assert_eq!(report.arp_conflicts.len(), 1);
        assert_eq!(report.arp_conflicts[0].mac_addresses.len(), 2);
        assert!(report.has_multiple_dhcp_servers());
        assert!(report.has_multiple_router_advertisers());
    }

    #[test]
    fn arp_conflicts_are_scoped_by_vlan_broadcast_domain() {
        let mut collector = Collector::new();
        let claims = [
            (vec![(false, 10)], [1, 0, 0, 0, 0, 1]),
            (vec![(false, 20)], [2, 0, 0, 0, 0, 2]),
            (vec![(false, 10)], [3, 0, 0, 0, 0, 3]),
            (vec![(true, 100), (false, 10)], [4, 0, 0, 0, 0, 4]),
            (vec![(true, 100), (false, 10)], [5, 0, 0, 0, 0, 5]),
        ];
        for (tags, mac) in claims {
            let mut packet = Packet::default();
            for (service_tag, vlan_id) in tags {
                if service_tag {
                    packet.push(Vlan8021ad {
                        vlan_id,
                        ..Vlan8021ad::default()
                    });
                } else {
                    packet.push(Vlan {
                        vlan_id,
                        ..Vlan::default()
                    });
                }
            }
            packet.push(Arp {
                sender_hardware: mac,
                sender_protocol: "10.0.0.1".parse().unwrap(),
                ..Arp::default()
            });
            collect(packet, &mut collector);
        }

        let report = collector.finish(&RunSummary::default());
        assert_eq!(report.arp_conflicts.len(), 2);
        assert!(
            report
                .arp_conflicts
                .iter()
                .all(|conflict| conflict.mac_addresses.len() == 2),
            "{report:?}"
        );
        assert_eq!(
            report.arp_conflicts[0].broadcast_domain,
            [EncapsulationIdentifier::Vlan { vlan_id: 10 }]
        );
        assert_eq!(
            report.arp_conflicts[1].broadcast_domain,
            [
                EncapsulationIdentifier::Vlan8021ad { vlan_id: 100 },
                EncapsulationIdentifier::Vlan { vlan_id: 10 },
            ]
        );
    }

    #[test]
    fn nested_dhcpv6_relay_messages_reveal_the_inner_server() {
        let mut collector = Collector::new();
        let mut inner = Dhcpv6::default();
        inner.edit(|inner| {
            inner.message_type = 7;
            inner.options = vec![Option6::server_identifier(
                Duid::enterprise(7, [1, 2, 3]).unwrap(),
            )];
        });
        let relay = Dhcpv6::relay_forward(
            1,
            "2001:db8::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            inner,
        );
        let mut packet = Packet::default();
        packet.push(relay);
        collect(packet, &mut collector);
        let report = collector.finish(&RunSummary::default());
        assert_eq!(report.dhcpv6_servers.len(), 1);
        assert!(
            report.dhcpv6_servers[0].starts_with("duid:2:"),
            "{report:?}"
        );
    }

    #[test]
    fn client_dhcp_messages_are_not_servers() {
        let mut collector = Collector::new();
        let mut packet = Packet::default();
        packet.push(Dhcpv4::default());
        collect(packet, &mut collector);
        let report = collector.finish(&RunSummary::default());
        assert!(report.dhcp_servers.is_empty());
    }
}
