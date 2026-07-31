// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use packetcraftr_packet::{Packet, diagnostic::DiagnosticSeverity, field::WireValue, layer::Raw};
use packetcraftr_protocol::{
    ipv6::Fragment as Ipv6Fragment,
    link::{Ethernet, Vlan},
    network::{Ipv4, Ipv6},
};

use super::*;

fn ipv4_fragment(
    identification: u16,
    offset: u16,
    more_fragments: bool,
    bytes: &'static [u8],
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            identification,
            fragment_offset: offset,
            more_fragments,
            protocol: WireValue::Exact(17),
            ..Ipv4::default()
        })
        .push(Raw::new(Bytes::from_static(bytes)));
    packet
}

fn ipv6_fragment(
    identification: u32,
    offset: u16,
    more_fragments: bool,
    bytes: &'static [u8],
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source: Ipv6Addr::LOCALHOST,
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Ipv6Fragment {
            next_header: WireValue::Exact(17),
            fragment_offset: offset,
            more_fragments,
            identification,
        })
        .push(Raw::new(Bytes::from_static(bytes)));
    packet
}

fn findings(packets: Vec<Packet>) -> Vec<expert::Finding> {
    expert_findings(&mut capture(packets), &AnalysisOptions::default())
        .into_iter()
        .filter(|finding| finding.code.starts_with("ip.fragment_"))
        .collect()
}

fn ethernet_ipv4_fragment(vlan: u16, identification: u16, bytes: &'static [u8]) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ethernet::default())
        .push(Vlan {
            vlan_id: vlan,
            ..Vlan::default()
        })
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            identification,
            more_fragments: true,
            protocol: WireValue::Exact(17),
            ..Ipv4::default()
        })
        .push(Raw::new(Bytes::from_static(bytes)));
    packet
}

#[test]
fn identical_ipv4_overlap_is_reported_once_even_when_datagram_completes() {
    let findings = findings(vec![
        ipv4_fragment(1, 0, true, b"abcdefghijklmnop"),
        ipv4_fragment(1, 1, true, b"ijklmnop"),
        ipv4_fragment(1, 2, false, b"tail"),
    ]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, "ip.fragment_overlap");
    assert_eq!(findings[0].severity, DiagnosticSeverity::Warning);
    assert_eq!(findings[0].number, 2);
    assert!(findings[0].message.contains("IPv4"));
    assert!(findings[0].message.contains("range 8..16 (8 byte(s))"));
}

#[test]
fn conflicting_ipv4_overlap_does_not_stop_later_frames() {
    let findings = findings(vec![
        ipv4_fragment(2, 0, true, b"abcdefghijklmnop"),
        ipv4_fragment(2, 1, true, b"XXXXXXXX"),
        ipv4_fragment(2, 2, false, b"tail"),
        ipv4_fragment(3, 0, true, b"abcdefgh"),
    ]);
    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.number, finding.code.as_str()))
            .collect::<Vec<_>>(),
        [
            (2, "ip.fragment_overlap_conflicting"),
            (4, "ip.fragment_incomplete"),
        ]
    );
    assert_eq!(findings[0].severity, DiagnosticSeverity::Error);
}

#[test]
fn ipv6_identical_and_conflicting_overlaps_are_distinguished() {
    let findings = findings(vec![
        ipv6_fragment(10, 0, true, b"abcdefghijklmnop"),
        ipv6_fragment(10, 1, true, b"ijklmnop"),
        ipv6_fragment(10, 2, false, b"tail"),
        ipv6_fragment(11, 0, true, b"abcdefghijklmnop"),
        ipv6_fragment(11, 1, true, b"XXXXXXXX"),
        ipv6_fragment(11, 2, false, b"tail"),
    ]);
    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.number, finding.code.as_str()))
            .collect::<Vec<_>>(),
        [
            (2, "ip.fragment_overlap"),
            (5, "ip.fragment_overlap_conflicting"),
        ]
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.message.contains("IPv6"))
    );
}

#[test]
fn clean_out_of_order_completion_is_not_an_anomaly() {
    assert!(
        findings(vec![
            ipv4_fragment(4, 1, false, b"tail"),
            ipv4_fragment(4, 0, true, b"abcdefgh"),
        ])
        .is_empty()
    );
}

#[test]
fn capture_end_reports_missing_prefix_and_known_internal_gap() {
    let prefix = findings(vec![ipv4_fragment(5, 1, false, b"tail")]);
    assert_eq!(
        prefix
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>(),
        ["ip.fragment_gap", "ip.fragment_incomplete"]
    );
    assert!(prefix[0].message.contains("0..8"));
    assert!(prefix[1].message.contains("final length 12"));
    assert!(prefix.iter().all(|finding| finding.number == 1));

    let internal = findings(vec![
        ipv4_fragment(6, 0, true, b"abcdefgh"),
        ipv4_fragment(6, 2, false, b"tail"),
    ]);
    assert_eq!(internal[0].code, "ip.fragment_gap");
    assert!(internal[0].message.contains("8..16"));
    assert_eq!(internal[1].code, "ip.fragment_incomplete");
    assert!(internal[1].message.contains("2 fragment(s)"));
}

#[test]
fn capture_end_with_no_final_fragment_does_not_invent_a_tail_gap() {
    let findings = findings(vec![ipv4_fragment(7, 0, true, b"abcdefgh")]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, "ip.fragment_incomplete");
    assert!(findings[0].message.contains("final length unknown"));
}

#[test]
fn capture_time_expiry_is_attributed_to_the_frame_that_revealed_it() {
    let mut writer = Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    for (seconds, packet) in [
        (0, ipv4_fragment(8, 1, false, b"tail")),
        (31, ipv4_fragment(9, 0, true, b"abcdefgh")),
    ] {
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_secs(seconds),
                    LinkType::RAW,
                    build_bytes(packet),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let findings = expert_findings(&mut reader, &AnalysisOptions::default())
        .into_iter()
        .filter(|finding| finding.message.contains("identification 8"))
        .collect::<Vec<_>>();
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|finding| finding.number == 2));
}

#[test]
fn identical_fragment_keys_on_different_interfaces_do_not_overlap() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    let first = writer.add_interface(LinkType::RAW).unwrap();
    let second = writer.add_interface(LinkType::RAW).unwrap();
    for (interface, bytes) in [(first, b"abcdefgh" as &'static [u8]), (second, b"XXXXXXXX")] {
        let mut frame = Frame::new(
            UNIX_EPOCH,
            LinkType::RAW,
            build_bytes(ipv4_fragment(10, 0, true, bytes)),
        )
        .unwrap();
        frame.interface = Some(interface);
        writer.write_frame(&frame).unwrap();
    }
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let findings = expert_findings(&mut reader, &AnalysisOptions::default());
    assert!(
        findings
            .iter()
            .all(|finding| !finding.code.contains("fragment_overlap")),
        "{findings:?}"
    );
}

#[test]
fn identical_fragment_keys_on_different_vlans_do_not_overlap() {
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    for packet in [
        ethernet_ipv4_fragment(10, 11, b"abcdefgh"),
        ethernet_ipv4_fragment(20, 11, b"XXXXXXXX"),
    ] {
        writer
            .write_frame(&Frame::new(UNIX_EPOCH, LinkType::ETHERNET, build_bytes(packet)).unwrap())
            .unwrap();
    }
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let findings = expert_findings(&mut reader, &AnalysisOptions::default());
    assert!(
        findings
            .iter()
            .all(|finding| !finding.code.contains("fragment_overlap")),
        "{findings:?}"
    );
}
