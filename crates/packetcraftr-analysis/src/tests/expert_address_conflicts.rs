// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use packetcraftr_packet::Packet;
use packetcraftr_protocol::{
    link::{Arp, Ethernet, Vlan, Vlan8021ad},
    network::Ipv4,
};

use super::*;

const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
const MAC_C: [u8; 6] = [0x02, 0, 0, 0, 0, 3];
const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

fn ethernet(mac: [u8; 6]) -> Ethernet {
    Ethernet {
        source: mac,
        destination: [0xff; 6],
        ..Ethernet::default()
    }
}

fn ipv4_claim(mac: [u8; 6], address: Ipv4Addr) -> Packet {
    let mut packet = Packet::new();
    packet.push(ethernet(mac)).push(Ipv4 {
        source: address,
        destination: Ipv4Addr::BROADCAST,
        ..Ipv4::default()
    });
    packet
}

fn arp_claim(mac: [u8; 6], address: Ipv4Addr) -> Packet {
    let mut packet = Packet::new();
    packet.push(ethernet(mac)).push(Arp {
        sender_hardware: mac,
        sender_protocol: address,
        target_protocol: address,
        ..Arp::default()
    });
    packet
}

fn vlan_claim(mac: [u8; 6], address: Ipv4Addr, tags: &[(bool, u16)]) -> Packet {
    let mut packet = Packet::new();
    packet.push(ethernet(mac));
    for &(service, id) in tags {
        if service {
            packet.push(Vlan8021ad {
                vlan_id: id,
                ..Vlan8021ad::default()
            });
        } else {
            packet.push(Vlan {
                vlan_id: id,
                ..Vlan::default()
            });
        }
    }
    packet.push(Ipv4 {
        source: address,
        destination: Ipv4Addr::BROADCAST,
        ..Ipv4::default()
    });
    packet
}

fn findings_with_bound(packets: Vec<Packet>, max_claims: usize) -> Vec<expert::Finding> {
    let mut reader = {
        let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        for (index, packet) in packets.into_iter().enumerate() {
            writer
                .write_frame(
                    &Frame::new(
                        UNIX_EPOCH + Duration::from_secs(u64::try_from(index).unwrap()),
                        LinkType::ETHERNET,
                        build_bytes(packet),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        Reader::new(Cursor::new(writer.into_inner())).unwrap()
    };
    let mut collector = expert::ExpertCollector::new();
    let mut findings = Vec::new();
    let options = AnalysisOptions {
        limits: AnalysisLimits {
            max_flows: max_claims,
            ..AnalysisLimits::default()
        },
        ..AnalysisOptions::default()
    };
    let summary = run(&mut reader, registry(), &options, |record| {
        findings.extend(collector.observe(&record));
        Ok(())
    })
    .unwrap();
    let (trailing, _) = collector.finish(&summary);
    findings.extend(trailing);
    findings
        .into_iter()
        .filter(|finding| finding.code.ends_with("address_conflict"))
        .collect()
}

fn findings(packets: Vec<Packet>) -> Vec<expert::Finding> {
    findings_with_bound(packets, 16)
}

#[test]
fn arp_and_ipv4_share_claim_evidence_and_use_revealing_code() {
    let findings = findings(vec![
        arp_claim(MAC_A, ADDRESS),
        ipv4_claim(MAC_B, ADDRESS),
        ipv4_claim(MAC_B, ADDRESS),
        arp_claim(MAC_C, ADDRESS),
    ]);
    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.number, finding.code.as_str()))
            .collect::<Vec<_>>(),
        [(2, "ipv4.address_conflict"), (4, "arp.address_conflict"),]
    );
    assert!(findings[0].message.contains("02:00:00:00:00:01"));
    assert!(findings[0].message.contains("first seen frame 1"));
    assert!(findings[0].message.contains("02:00:00:00:00:02"));
    assert!(findings[0].message.contains("interface implicit"));
}

#[test]
fn distinct_vlan_and_qinq_stacks_do_not_share_claims() {
    let findings = findings(vec![
        vlan_claim(MAC_A, ADDRESS, &[(false, 10)]),
        vlan_claim(MAC_B, ADDRESS, &[(false, 20)]),
        vlan_claim(MAC_C, ADDRESS, &[(true, 10), (false, 20)]),
        vlan_claim(MAC_B, ADDRESS, &[(false, 20), (true, 10)]),
        vlan_claim(MAC_B, ADDRESS, &[(false, 10)]),
    ]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].number, 5);
    assert!(findings[0].message.contains("802.1Q:10"));
}

#[test]
fn pcapng_interfaces_scope_identical_addresses_independently() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    let first = writer.add_interface(LinkType::ETHERNET).unwrap();
    let second = writer.add_interface(LinkType::ETHERNET).unwrap();
    for (number, interface, packet) in [
        (0, first, ipv4_claim(MAC_A, ADDRESS)),
        (1, second, ipv4_claim(MAC_B, ADDRESS)),
        (2, first, ipv4_claim(MAC_C, ADDRESS)),
    ] {
        let mut frame = Frame::new(
            UNIX_EPOCH + Duration::from_secs(number),
            LinkType::ETHERNET,
            build_bytes(packet),
        )
        .unwrap();
        frame.interface = Some(interface);
        writer.write_frame(&frame).unwrap();
    }
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let findings = expert_findings(&mut reader, &AnalysisOptions::default())
        .into_iter()
        .filter(|finding| finding.code.ends_with("address_conflict"))
        .collect::<Vec<_>>();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].number, 3);
    assert!(findings[0].message.contains("interface 0"));
}

#[test]
fn tunneled_inner_ipv4_source_is_never_claimed_by_outer_ethernet() {
    let mut tunneled = Packet::new();
    tunneled
        .push(ethernet(MAC_B))
        .push(Ipv4 {
            source: Ipv4Addr::new(198, 51, 100, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Ipv4 {
            source: ADDRESS,
            destination: Ipv4Addr::new(192, 0, 2, 20),
            ..Ipv4::default()
        });
    assert!(findings(vec![ipv4_claim(MAC_A, ADDRESS), tunneled]).is_empty());
}

#[test]
fn unusable_addresses_and_macs_are_ignored() {
    assert!(
        findings(vec![
            arp_claim(MAC_A, Ipv4Addr::UNSPECIFIED),
            arp_claim(MAC_A, Ipv4Addr::new(127, 0, 0, 1)),
            arp_claim(MAC_B, Ipv4Addr::new(127, 0, 0, 1)),
            arp_claim(MAC_A, Ipv4Addr::new(224, 0, 0, 1)),
            arp_claim(MAC_B, Ipv4Addr::new(224, 0, 0, 1)),
            arp_claim(MAC_A, Ipv4Addr::new(240, 0, 0, 1)),
            arp_claim(MAC_B, Ipv4Addr::new(240, 0, 0, 1)),
            arp_claim([0; 6], ADDRESS),
            arp_claim([0x01, 0, 0, 0, 0, 1], ADDRESS),
            ipv4_claim(MAC_A, Ipv4Addr::UNSPECIFIED),
            ipv4_claim(MAC_A, Ipv4Addr::new(127, 0, 0, 1)),
            ipv4_claim(MAC_B, Ipv4Addr::new(224, 0, 0, 1)),
            ipv4_claim(MAC_B, Ipv4Addr::new(240, 0, 0, 1)),
            ipv4_claim([0xff; 6], ADDRESS),
        ])
        .is_empty()
    );
}

#[test]
fn claim_bound_saturates_without_evicting_or_growing_evidence() {
    let findings = findings_with_bound(
        vec![
            arp_claim(MAC_A, ADDRESS),
            arp_claim(MAC_B, ADDRESS),
            arp_claim(MAC_C, ADDRESS),
            arp_claim(MAC_C, Ipv4Addr::new(192, 0, 2, 11)),
        ],
        2,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].number, 2);
}
