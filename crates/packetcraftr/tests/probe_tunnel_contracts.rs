// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::probe::Transport;
use packetcraftr::scan::{self, Classification};
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    frame::{Frame, LinkType},
    packet::Packet,
    protocol::{
        application::dns::Dns,
        builtin,
        link::Ethernet,
        network::Ipv4,
        transport::{Tcp, Udp},
        tunnel::{Geneve, Vxlan},
    },
};
use std::{net::Ipv4Addr, time::SystemTime};

fn tunnel(reply: bool, geneve: bool, tcp: bool) -> Packet {
    let mut packet = Packet::new();
    let (client, server) = (Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2));
    let (inner_client, inner_server) = (
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 2),
    );
    packet.push(Ipv4 {
        source: if reply { server } else { client },
        destination: if reply { client } else { server },
        ..Ipv4::default()
    });
    let port = if geneve { 6081 } else { 4789 };
    packet.push(Udp {
        source_port: if reply { port } else { 50000 },
        destination_port: if reply { 50000 } else { port },
        ..Udp::default()
    });
    if geneve {
        packet.push(Geneve::default());
    } else {
        packet.push(Vxlan::default());
    }
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: if reply { inner_server } else { inner_client },
        destination: if reply { inner_client } else { inner_server },
        ..Ipv4::default()
    });
    if tcp {
        packet.push(Tcp {
            source_port: if reply { 80 } else { 50001 },
            destination_port: if reply { 50001 } else { 80 },
            sequence: 100,
            acknowledgment: 101,
            flags: if reply { Tcp::SYN | Tcp::ACK } else { Tcp::SYN },
            ..Tcp::default()
        });
    } else {
        packet.push(Udp {
            source_port: if reply { 53 } else { 50001 },
            destination_port: if reply { 50001 } else { 53 },
            ..Udp::default()
        });
        let mut dns = Dns::default();
        dns.edit(|dns| {
            dns.id = if reply { 2 } else { 1 };
            dns.response = reply;
        });
        packet.push(dns);
    }
    packet
}

#[test]
fn udp_probes_validate_inner_tunnel_flows_before_reporting_open() {
    let registry = builtin::registry();
    for geneve in [false, true] {
        for tcp in [false, true] {
            let request = tunnel(false, geneve, tcp);
            let built = Builder::new(registry.clone())
                .build(
                    tunnel(true, geneve, tcp),
                    Default::default(),
                    Default::default(),
                )
                .unwrap();
            let frame = Frame::new(SystemTime::now(), LinkType::RAW, built.bytes).unwrap();
            let response = Dissector::new(registry.clone())
                .decode(frame, Default::default())
                .unwrap();
            assert_eq!(
                scan::classify_response(&registry, Transport::Udp, &request, &response)
                    .unwrap()
                    .classification,
                Classification::Open
            );
            for (index, field) in [
                (0, "source"),
                (1, "source_port"),
                (4, "source"),
                (4, "destination"),
                (5, "source_port"),
                (5, "destination_port"),
            ] {
                let mut unrelated = response.clone();
                let value = if field.contains("port") {
                    12345_u16.into()
                } else {
                    Ipv4Addr::new(203, 0, 113, 9).into()
                };
                unrelated
                    .packet
                    .layer_mut(index)
                    .unwrap()
                    .set_field(field, value)
                    .unwrap();
                assert!(
                    scan::classify_response(&registry, Transport::Udp, &request, &unrelated)
                        .is_none(),
                    "geneve={geneve}, tcp={tcp}, {index}.{field}"
                );
            }
            if tcp {
                let mut unrelated = response.clone();
                unrelated.packet.get_mut::<Tcp>().unwrap().acknowledgment += 1;
                assert!(
                    scan::classify_response(&registry, Transport::Udp, &request, &unrelated)
                        .is_none()
                );
            } else {
                let mut unrelated = response.clone();
                unrelated.packet.remove(6).unwrap();
                unrelated.packet.remove(5).unwrap();
                assert!(
                    scan::classify_response(&registry, Transport::Udp, &request, &unrelated)
                        .is_none()
                );
            }
        }
    }
}
