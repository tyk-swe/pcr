// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::packets::{ipv4, ipv6};
use packetcraftr_core::{
    build::Builder,
    frame::{Frame, LinkType},
    layer::{Layer, Raw},
    packet::Packet,
    protocol::{
        builtin, checksum, checksum_parts,
        link::Ethernet,
        transport::{Tcp, Udp},
    },
    transform::{
        self, AddressMap, ChecksumMode, HeaderRewrite, InvalidInput, IpMapping,
        MAX_ADDRESS_MAP_ENTRIES, MacMapping, RewriteLimits, Unsupported, rules::Rules,
    },
};
use std::time::UNIX_EPOCH;

const FIRST_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0, 0, 1];
const SECOND_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0, 0, 2];

/// Bare IPv4 carrying `transport` between the given addresses.
fn ipv4_frame(source: [u8; 4], destination: [u8; 4], transport: impl Layer) -> Frame {
    let mut packet = Packet::new();
    packet.push(ipv4(source, destination));
    packet.push(transport);
    packet.push(Raw::new(vec![0x51; 21]));
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    Frame::new(UNIX_EPOCH, LinkType::IPV4, built.bytes).unwrap()
}

fn udp() -> Udp {
    Udp {
        source_port: 40000,
        destination_port: 40001,
        ..Default::default()
    }
}

fn tcp() -> Tcp {
    Tcp {
        source_port: 40000,
        destination_port: 40001,
        ..Default::default()
    }
}

fn ethernet_frame(source: [u8; 6], destination: [u8; 6]) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ethernet {
        source,
        destination,
        ..Default::default()
    });
    packet.push(ipv4([192, 0, 2, 1], [198, 51, 100, 2]));
    packet.push(udp());
    packet.push(Raw::new(vec![0x51; 21]));
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    Frame::new(UNIX_EPOCH, LinkType::ETHERNET, built.bytes).unwrap()
}

fn ips(entries: &[&str]) -> Vec<IpMapping> {
    entries.iter().map(|entry| entry.parse().unwrap()).collect()
}

fn macs(entries: &[&str]) -> Vec<MacMapping> {
    entries.iter().map(|entry| entry.parse().unwrap()).collect()
}

fn map(ip_entries: &[&str], mac_entries: &[&str]) -> AddressMap {
    AddressMap::new(&ips(ip_entries), &macs(mac_entries)).unwrap()
}

fn apply(map: &AddressMap, frame: &Frame) -> Result<Frame, transform::Error> {
    map.apply(frame, RewriteLimits::default())
}

fn assert_ipv4_checksums(frame: &Frame, protocol: u8) {
    let bytes = frame.bytes();
    assert_eq!(checksum(&bytes[..20]), 0, "IPv4 header checksum");
    let length = u16::try_from(bytes.len() - 20).unwrap().to_be_bytes();
    assert_eq!(
        checksum_parts(&[&bytes[12..20], &[0, protocol], &length, &bytes[20..]]),
        0,
        "transport checksum"
    );
}

#[test]
fn a_prefix_mapping_keeps_host_bits_for_source_and_destination() {
    let table = map(
        &[
            "192.0.2.0/24=198.51.100.0/24",
            "198.51.100.0/24=203.0.113.0/24",
        ],
        &[],
    );
    for (original, protocol) in [
        (ipv4_frame([192, 0, 2, 7], [198, 51, 100, 9], tcp()), 6),
        (ipv4_frame([192, 0, 2, 7], [198, 51, 100, 9], udp()), 17),
    ] {
        let mapped = apply(&table, &original).unwrap();
        assert_eq!(mapped.bytes()[12..16], [198, 51, 100, 7]);
        assert_eq!(mapped.bytes()[16..20], [203, 0, 113, 9]);
        assert_eq!(mapped.timestamp, original.timestamp);
        assert_ipv4_checksums(&mapped, protocol);
    }
}

#[test]
fn single_host_entries_remap_independently_and_leave_other_hosts_untouched() {
    let table = map(&["192.0.2.1=203.0.113.9", "192.0.2.2=203.0.113.10"], &[]);
    let original = ipv4_frame([192, 0, 2, 1], [192, 0, 2, 2], udp());
    let mapped = apply(&table, &original).unwrap();
    assert_eq!(mapped.bytes()[12..16], [203, 0, 113, 9]);
    assert_eq!(mapped.bytes()[16..20], [203, 0, 113, 10]);
    assert_ipv4_checksums(&mapped, 17);
    let half = ipv4_frame([192, 0, 2, 1], [192, 0, 2, 3], udp());
    let mapped = apply(&table, &half).unwrap();
    assert_eq!(mapped.bytes()[12..16], [203, 0, 113, 9]);
    assert_eq!(mapped.bytes()[16..20], [192, 0, 2, 3]);
    assert_ipv4_checksums(&mapped, 17);
    let unmatched = ipv4_frame([192, 0, 2, 3], [192, 0, 2, 4], udp());
    assert_eq!(
        apply(&table, &unmatched).unwrap().bytes(),
        unmatched.bytes()
    );
}

#[test]
fn ipv6_prefixes_remap_with_the_pseudo_header_repaired() {
    let table = map(&["2001:db8::/64=2001:db8:0:1::/64"], &[]);
    let mut packet = Packet::new();
    packet.push(ipv6("2001:db8::5", "2001:db8:ffff::2"));
    packet.push(udp());
    packet.push(Raw::new(vec![0x51; 21]));
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    let original = Frame::new(UNIX_EPOCH, LinkType::IPV6, built.bytes).unwrap();
    let mapped = apply(&table, &original).unwrap();
    let bytes = mapped.bytes();
    assert_eq!(
        bytes[8..24],
        "2001:db8:0:1::5"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
    );
    assert_eq!(bytes[24..40], original.bytes()[24..40]);
    let length = u32::try_from(bytes.len() - 40).unwrap().to_be_bytes();
    assert_eq!(
        checksum_parts(&[&bytes[8..40], &length, &[0, 0, 0, 17], &bytes[40..]]),
        0
    );
    // An IPv4 table never matches an IPv6 frame.
    let table = map(&["192.0.2.0/24=198.51.100.0/24"], &[]);
    assert_eq!(apply(&table, &original).unwrap().bytes(), original.bytes());
}

#[test]
fn mac_entries_rewrite_only_the_matching_ethernet_address() {
    let table = map(&[], &["aa:bb:cc:00:00:01=02:00:00:00:00:01"]);
    let original = ethernet_frame(FIRST_MAC, SECOND_MAC);
    let mapped = apply(&table, &original).unwrap();
    assert_eq!(mapped.bytes()[..6], SECOND_MAC);
    assert_eq!(mapped.bytes()[6..12], [2, 0, 0, 0, 0, 1]);
    assert_eq!(mapped.bytes()[12..], original.bytes()[12..]);
    let swapped = ethernet_frame(SECOND_MAC, FIRST_MAC);
    let mapped = apply(&table, &swapped).unwrap();
    assert_eq!(mapped.bytes()[..6], [2, 0, 0, 0, 0, 1]);
    assert_eq!(mapped.bytes()[6..12], SECOND_MAC);
    let unmatched = ethernet_frame(SECOND_MAC, SECOND_MAC);
    assert_eq!(
        apply(&table, &unmatched).unwrap().bytes(),
        unmatched.bytes()
    );
    // Raw IP frames carry no Ethernet address to match.
    let raw = ipv4_frame([192, 0, 2, 1], [198, 51, 100, 2], udp());
    assert_eq!(apply(&table, &raw).unwrap().bytes(), raw.bytes());
}

#[test]
fn invalid_entries_and_tables_fail_with_typed_errors() {
    for (text, expected) in [
        ("192.0.2.1", InvalidInput::AddressMapSyntax),
        ("192.0.2.1=bogus", InvalidInput::AddressMapAddress),
        ("192.0.2.1=2001:db8::1", InvalidInput::AddressMapFamilies),
        (
            "192.0.2.0/24=198.51.100.0/25",
            InvalidInput::AddressMapPrefix,
        ),
        ("192.0.2.0/24=198.51.100.1", InvalidInput::AddressMapPrefix),
        (
            "192.0.2.0/33=198.51.100.0/33",
            InvalidInput::AddressMapPrefix,
        ),
        ("192.0.2.0/x=198.51.100.0/x", InvalidInput::AddressMapPrefix),
        (
            "192.0.2.7/24=198.51.100.0/24",
            InvalidInput::AddressMapHostBits,
        ),
    ] {
        assert!(
            matches!(
                text.parse::<IpMapping>(),
                Err(transform::Error::Invalid(actual)) if actual == expected
            ),
            "{text}"
        );
    }
    for text in ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:01=zz", "1=2"] {
        assert!(text.parse::<MacMapping>().is_err(), "{text}");
    }
    for entries in [
        vec!["192.0.2.0/24=198.51.100.0/24", "192.0.2.5=203.0.113.1"],
        vec!["192.0.2.5=203.0.113.1", "192.0.2.0/24=198.51.100.0/24"],
        vec!["192.0.2.1=203.0.113.1", "192.0.2.1=203.0.113.2"],
        vec!["2001:db8::/32=2001:db9::/32", "2001:db8::1=2001:db9::1"],
    ] {
        assert!(
            matches!(
                AddressMap::new(&ips(&entries), &[]),
                Err(transform::Error::Invalid(InvalidInput::AddressMapOverlap))
            ),
            "{entries:?}"
        );
    }
    // Different families never overlap, and a repeated MAC source is refused.
    assert!(AddressMap::new(&ips(&["0.0.0.0/0=0.0.0.0/0", "::/0=::/0"]), &[]).is_ok());
    assert!(matches!(
        AddressMap::new(
            &[],
            &macs(&[
                "aa:bb:cc:00:00:01=02:00:00:00:00:01",
                "aa:bb:cc:00:00:01=02:00:00:00:00:02"
            ])
        ),
        Err(transform::Error::Invalid(InvalidInput::AddressMapOverlap))
    ));
}

#[test]
fn the_table_holds_at_most_the_documented_entries() {
    let entry = |index: usize| {
        let [_, _, high, low] = u32::try_from(index).unwrap().to_be_bytes();
        format!("10.{high}.{low}.0/24=172.16.{low}.0/24")
            .parse::<IpMapping>()
            .unwrap()
    };
    let full: Vec<_> = (0..MAX_ADDRESS_MAP_ENTRIES).map(entry).collect();
    assert!(AddressMap::new(&full, &[]).is_ok());
    let mut over = full;
    over.push(entry(MAX_ADDRESS_MAP_ENTRIES));
    assert!(matches!(
        AddressMap::new(&over, &[]),
        Err(transform::Error::Limit {
            limit: MAX_ADDRESS_MAP_ENTRIES,
            ..
        })
    ));
    // MAC entries share the budget.
    let mac: MacMapping = "aa:bb:cc:00:00:01=02:00:00:00:00:01".parse().unwrap();
    assert!(matches!(
        AddressMap::new(&over[..MAX_ADDRESS_MAP_ENTRIES], &[mac]),
        Err(transform::Error::Limit { .. })
    ));
}

#[test]
fn frames_that_cannot_be_repaired_fail_only_when_an_address_matches() {
    let table = map(&["192.0.2.0/24=198.51.100.0/24"], &[]);
    let original = ipv4_frame([192, 0, 2, 1], [203, 0, 113, 2], udp());
    let fragments = transform::fragment(
        &original,
        transform::FragmentOptions {
            mtu: 36,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(fragments.len() > 1);
    assert!(matches!(
        apply(&table, &fragments[0]),
        Err(transform::Error::Unsupported(
            Unsupported::ChecksumOverFragment
        ))
    ));
    let unrelated = map(&["10.0.0.0/8=11.0.0.0/8"], &[]);
    assert_eq!(
        apply(&unrelated, &fragments[0]).unwrap().bytes(),
        fragments[0].bytes()
    );
    let truncated = common::truncated(&original, 4);
    assert!(matches!(
        apply(&table, &truncated),
        Err(transform::Error::Invalid(
            InvalidInput::RewriteTruncatedCapture
        ))
    ));
    assert_eq!(
        apply(&unrelated, &truncated).unwrap().bytes(),
        truncated.bytes()
    );
}

#[test]
fn a_rule_applies_the_map_after_its_header_edits_and_counts_as_a_header_edit() {
    let table = map(&["192.0.2.0/24=198.51.100.0/24"], &[]);
    let rules = Rules::single(
        None,
        HeaderRewrite {
            source_port: Some(5000),
            ..Default::default()
        },
        &[],
        ChecksumMode::Repair,
        &builtin::registry(),
    )
    .unwrap()
    .with_address_map(table);
    assert!(rules.has_header_edits());
    let original = ipv4_frame([192, 0, 2, 7], [203, 0, 113, 2], udp());
    let dissector = packetcraftr_core::decode::Dissector::new(builtin::registry());
    let changed = rules
        .apply(
            &original,
            &dissector,
            RewriteLimits::default(),
            |_: &String| Ok(true),
            |_, _| {},
        )
        .unwrap();
    assert_eq!(changed.bytes()[12..16], [198, 51, 100, 7]);
    assert_eq!(changed.bytes()[20..22], 5000_u16.to_be_bytes());
    assert_ipv4_checksums(&changed, 17);
}
