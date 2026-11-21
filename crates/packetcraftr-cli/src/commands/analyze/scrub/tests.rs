// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_core::protocol::checksum_parts;

const V4_SOURCE: [u8; 4] = [198, 51, 100, 9];
const V4_DESTINATION: [u8; 4] = [203, 0, 113, 7];
const V6_SOURCE: [u8; 16] = [0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
const V6_DESTINATION: [u8; 16] = [0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];

fn transport_checksum(source: IpAddr, destination: IpAddr, protocol: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::new();
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&[0, protocol]);
            pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, protocol]);
        }
        _ => unreachable!(),
    }
    checksum_parts(&[&pseudo, segment])
}

fn udp_segment(source: IpAddr, destination: IpAddr, payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::with_capacity(8 + payload.len());
    segment.extend_from_slice(&12_345_u16.to_be_bytes());
    segment.extend_from_slice(&53_u16.to_be_bytes());
    segment.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    let checksum = transport_checksum(source, destination, 17, &segment);
    segment[6..8].copy_from_slice(&(if checksum == 0 { 0xffff } else { checksum }).to_be_bytes());
    segment
}

fn tcp_segment(source: IpAddr, destination: IpAddr, payload: &[u8]) -> Vec<u8> {
    let mut segment = vec![0_u8; 20];
    segment[0..2].copy_from_slice(&12_345_u16.to_be_bytes());
    segment[2..4].copy_from_slice(&443_u16.to_be_bytes());
    segment[12] = 0x50;
    segment[13] = 0x18;
    segment[14..16].copy_from_slice(&4096_u16.to_be_bytes());
    segment.extend_from_slice(payload);
    let checksum = transport_checksum(source, destination, 6, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    segment
}

fn ipv4_frame(protocol: u8, chunk: &[u8], flags_and_offset: u16) -> Frame {
    let total = 20 + chunk.len();
    let mut bytes = vec![0_u8; total];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&7_u16.to_be_bytes());
    bytes[6..8].copy_from_slice(&flags_and_offset.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&V4_SOURCE);
    bytes[16..20].copy_from_slice(&V4_DESTINATION);
    let checksum = checksum_parts(&[&bytes[..20]]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes[20..].copy_from_slice(chunk);
    Frame::new(None, LinkType::RAW, bytes).unwrap()
}

fn ipv4_option_frame(kind: u8, segment: &[u8]) -> Frame {
    let total = 28 + segment.len();
    let mut bytes = vec![0_u8; total];
    bytes[0] = 0x47;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&V4_SOURCE);
    bytes[16..20].copy_from_slice(&V4_DESTINATION);
    bytes[20] = kind;
    bytes[21] = 7;
    bytes[22] = 4;
    bytes[23..27].copy_from_slice(&V4_SOURCE);
    let checksum = checksum_parts(&[&bytes[..28]]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes[28..].copy_from_slice(segment);
    Frame::new(None, LinkType::RAW, bytes).unwrap()
}

fn ipv4_addresses(ip: &[u8]) -> (IpAddr, IpAddr) {
    (
        IpAddr::from(<[u8; 4]>::try_from(&ip[12..16]).unwrap()),
        IpAddr::from(<[u8; 4]>::try_from(&ip[16..20]).unwrap()),
    )
}

fn assert_ipv4_header_checksum(ip: &[u8]) {
    assert_eq!(checksum_parts(&[&ip[..20]]), 0);
}

#[test]
fn fallback_rewrites_keep_valid_ipv4_and_transport_checksums() {
    let source = IpAddr::from(V4_SOURCE);
    let destination = IpAddr::from(V4_DESTINATION);
    for (protocol, segment) in [
        (17_u8, udp_segment(source, destination, b"purple-team")),
        (6_u8, tcp_segment(source, destination, b"purple-team")),
    ] {
        let frame = ipv4_frame(protocol, &segment, 0);
        let patched = fallback_patch(&frame, &mut Pseudonyms::default()).unwrap();
        let ip = patched.bytes();
        assert_ipv4_header_checksum(ip);
        let (mapped_source, mapped_destination) = ipv4_addresses(ip);
        assert_ne!(mapped_source, source);
        assert_ne!(mapped_destination, destination);
        assert_eq!(
            transport_checksum(mapped_source, mapped_destination, protocol, &ip[20..]),
            0
        );
    }
}

#[test]
fn fallback_adjusts_udp_checksum_from_the_first_fragment_only() {
    let segment = udp_segment(
        IpAddr::from(V4_SOURCE),
        IpAddr::from(V4_DESTINATION),
        &[7_u8; 24],
    );
    let frame = ipv4_frame(17, &segment[..16], 0x2000);
    let patched = fallback_patch(&frame, &mut Pseudonyms::default()).unwrap();
    let ip = patched.bytes();
    assert_ipv4_header_checksum(ip);
    let mut reassembled = ip[20..].to_vec();
    reassembled.extend_from_slice(&segment[16..]);
    let (source, destination) = ipv4_addresses(ip);
    assert_eq!(transport_checksum(source, destination, 17, &reassembled), 0);
}

#[test]
fn fallback_adjusts_tcp_checksum_carried_by_a_later_fragment() {
    let segment = tcp_segment(
        IpAddr::from(V4_SOURCE),
        IpAddr::from(V4_DESTINATION),
        &[9_u8; 12],
    );
    let mut names = Pseudonyms::default();
    let first = fallback_patch(&ipv4_frame(6, &segment[..8], 0x2000), &mut names).unwrap();
    let second = fallback_patch(&ipv4_frame(6, &segment[8..], 1), &mut names).unwrap();
    assert_ipv4_header_checksum(first.bytes());
    assert_ipv4_header_checksum(second.bytes());
    let mut reassembled = first.bytes()[20..].to_vec();
    reassembled.extend_from_slice(&second.bytes()[20..]);
    let (source, destination) = ipv4_addresses(second.bytes());
    assert_eq!(transport_checksum(source, destination, 6, &reassembled), 0);
}

#[test]
fn fallback_rewrites_keep_valid_ipv6_transport_checksums() {
    let source = IpAddr::from(V6_SOURCE);
    let destination = IpAddr::from(V6_DESTINATION);
    let segment = udp_segment(source, destination, &[5_u8; 24]);

    let mut plain = vec![0_u8; 40 + segment.len()];
    plain[0] = 0x60;
    plain[4..6].copy_from_slice(&(segment.len() as u16).to_be_bytes());
    plain[6] = 17;
    plain[7] = 64;
    plain[8..24].copy_from_slice(&V6_SOURCE);
    plain[24..40].copy_from_slice(&V6_DESTINATION);
    plain[40..].copy_from_slice(&segment);
    let patched = fallback_patch(
        &Frame::new(None, LinkType::RAW, plain).unwrap(),
        &mut Pseudonyms::default(),
    )
    .unwrap();
    let ip = patched.bytes();
    let (mapped_source, mapped_destination) = (
        IpAddr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap()),
        IpAddr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap()),
    );
    assert_eq!(
        transport_checksum(mapped_source, mapped_destination, 17, &ip[40..]),
        0
    );

    let first_chunk = &segment[..16];
    let mut fragmented = vec![0_u8; 48 + first_chunk.len()];
    fragmented[0] = 0x60;
    fragmented[4..6].copy_from_slice(&((8 + first_chunk.len()) as u16).to_be_bytes());
    fragmented[6] = 44;
    fragmented[7] = 64;
    fragmented[8..24].copy_from_slice(&V6_SOURCE);
    fragmented[24..40].copy_from_slice(&V6_DESTINATION);
    fragmented[40] = 17;
    fragmented[43] = 1;
    fragmented[44..48].copy_from_slice(&7_u32.to_be_bytes());
    fragmented[48..].copy_from_slice(first_chunk);
    let patched = fallback_patch(
        &Frame::new(None, LinkType::RAW, fragmented).unwrap(),
        &mut Pseudonyms::default(),
    )
    .unwrap();
    let ip = patched.bytes();
    let mut reassembled = ip[48..].to_vec();
    reassembled.extend_from_slice(&segment[16..]);
    let (mapped_source, mapped_destination) = (
        IpAddr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap()),
        IpAddr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap()),
    );
    assert_eq!(
        transport_checksum(mapped_source, mapped_destination, 17, &reassembled),
        0
    );
}

#[test]
fn fallback_scrubs_deeply_tagged_ethernet_frames() {
    let segment = udp_segment(
        IpAddr::from(V4_SOURCE),
        IpAddr::from(V4_DESTINATION),
        b"tagged",
    );
    let raw = ipv4_frame(17, &segment, 0);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[2, 0, 0, 0, 0, 2]);
    bytes.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    for tag in 0..5_u16 {
        bytes.extend_from_slice(&0x8100_u16.to_be_bytes());
        bytes.extend_from_slice(&(tag + 1).to_be_bytes());
    }
    bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
    bytes.extend_from_slice(raw.bytes());
    let frame = Frame::new(None, LinkType::ETHERNET, bytes).unwrap();
    let patched = fallback_patch(&frame, &mut Pseudonyms::default()).unwrap();
    assert_eq!(&patched.bytes()[0..6], &[2, 0, 0, 0, 0, 1]);
    let ip = &patched.bytes()[34..];
    assert_ipv4_header_checksum(ip);
    let (source, destination) = ipv4_addresses(ip);
    assert_eq!(transport_checksum(source, destination, 17, &ip[20..]), 0);
}

#[test]
fn scrub_pseudonymizes_outer_mac_on_encapsulated_ethernet() {
    let segment = udp_segment(
        IpAddr::from(V4_SOURCE),
        IpAddr::from(V4_DESTINATION),
        b"encapsulated",
    );
    let raw = ipv4_frame(17, &segment, 0);
    for (ether_type, prefix) in [
        (0x8864_u16, vec![0x11, 0, 0, 1, 0, 42, 0, 0x21]),
        (0x8847_u16, vec![0, 0, 0x11, 64]),
    ] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[2, 0, 0, 0, 0, 9]);
        bytes.extend_from_slice(&[2, 0, 0, 0, 0, 8]);
        bytes.extend_from_slice(&ether_type.to_be_bytes());
        bytes.extend_from_slice(&prefix);
        bytes.extend_from_slice(raw.bytes());
        let frame = Frame::new(None, LinkType::ETHERNET, bytes).unwrap();
        let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());
        let scrubbed =
            scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).unwrap();
        assert!(matches!(
            &scrubbed.bytes()[0..6],
            [2, 0, 0, 0, 0, 1] | [2, 0, 0, 0, 0, 2]
        ));
        assert!(matches!(
            &scrubbed.bytes()[6..12],
            [2, 0, 0, 0, 0, 1] | [2, 0, 0, 0, 0, 2]
        ));
        assert_ne!(&scrubbed.bytes()[0..6], &scrubbed.bytes()[6..12]);
        let ip_offset = 14 + prefix.len();
        assert_eq!(&scrubbed.bytes()[ip_offset..], raw.bytes());
    }
}

#[test]
fn scrub_refuses_outer_headers_with_embedded_addresses() {
    let segment = udp_segment(
        IpAddr::from(V4_SOURCE),
        IpAddr::from(V4_DESTINATION),
        b"routed",
    );
    let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());
    for kind in [7_u8, 131] {
        let frame = ipv4_option_frame(kind, &segment);
        assert!(fallback_patch(&frame, &mut Pseudonyms::default()).is_none());
        assert!(scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).is_err());
    }

    let segment = udp_segment(
        IpAddr::from(V6_SOURCE),
        IpAddr::from(V6_DESTINATION),
        b"routed",
    );
    let mut bytes = vec![0_u8; 64 + segment.len()];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&((24 + segment.len()) as u16).to_be_bytes());
    bytes[6] = 43;
    bytes[7] = 64;
    bytes[8..24].copy_from_slice(&V6_SOURCE);
    bytes[24..40].copy_from_slice(&V6_DESTINATION);
    bytes[40] = 17;
    bytes[41] = 2;
    bytes[43] = 1;
    bytes[48..64].copy_from_slice(&V6_SOURCE);
    bytes[64..].copy_from_slice(&segment);
    let frame = Frame::new(None, LinkType::RAW, bytes).unwrap();
    assert!(fallback_patch(&frame, &mut Pseudonyms::default()).is_none());
    assert!(scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).is_err());
}

#[test]
fn scrub_refuses_embedded_addresses_on_cooked_links() {
    let segment = udp_segment(
        IpAddr::from(V4_SOURCE),
        IpAddr::from(V4_DESTINATION),
        b"cooked",
    );
    let raw = ipv4_option_frame(7, &segment);
    let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());

    let mut sll = vec![0_u8; 16];
    sll[4..6].copy_from_slice(&6_u16.to_be_bytes());
    sll[14..16].copy_from_slice(&0x0800_u16.to_be_bytes());
    sll.extend_from_slice(raw.bytes());
    let frame = Frame::new(None, LinkType::LINUX_SLL, sll).unwrap();
    assert!(fallback_patch(&frame, &mut Pseudonyms::default()).is_none());
    assert_eq!(
        scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000)
            .unwrap_err()
            .message,
        "scrub cannot pseudonymize IP addresses on this link type"
    );

    let mut sll2 = vec![0_u8; 20];
    sll2[0..2].copy_from_slice(&0x0800_u16.to_be_bytes());
    sll2[11] = 6;
    sll2.extend_from_slice(raw.bytes());
    let frame = Frame::new(None, LinkType::LINUX_SLL2, sll2).unwrap();
    assert!(fallback_patch(&frame, &mut Pseudonyms::default()).is_none());
    assert_eq!(
        scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000)
            .unwrap_err()
            .message,
        "scrub cannot pseudonymize IP addresses on this link type"
    );
}

#[test]
fn scrub_pseudonymizes_cooked_addresses_on_non_ip_frames() {
    let sender_mac = [2, 0, 0, 0, 0, 8];
    let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());

    let mut sll = vec![0_u8; 16];
    sll[4..6].copy_from_slice(&6_u16.to_be_bytes());
    sll[6..12].copy_from_slice(&sender_mac);
    sll[14..16].copy_from_slice(&0x88cc_u16.to_be_bytes());
    sll.extend_from_slice(b"lldp-payload");
    let frame = Frame::new(None, LinkType::LINUX_SLL, sll).unwrap();
    let scrubbed = scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).unwrap();
    assert_eq!(&scrubbed.bytes()[6..12], &[2, 0, 0, 0, 0, 1]);

    let mut sll2 = vec![0_u8; 20];
    sll2[0..2].copy_from_slice(&0x88cc_u16.to_be_bytes());
    sll2[11] = 6;
    sll2[12..18].copy_from_slice(&sender_mac);
    sll2.extend_from_slice(b"lldp-payload");
    let frame = Frame::new(None, LinkType::LINUX_SLL2, sll2).unwrap();
    let scrubbed = scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).unwrap();
    assert_eq!(&scrubbed.bytes()[12..18], &[2, 0, 0, 0, 0, 1]);
}

#[test]
fn scrub_refuses_ip_on_unsupported_link_types() {
    let segment = udp_segment(
        IpAddr::from(V4_SOURCE),
        IpAddr::from(V4_DESTINATION),
        b"loopback-link",
    );
    let raw = ipv4_frame(17, &segment, 0);
    let mut bytes = vec![0, 0, 0, 2];
    bytes.extend_from_slice(raw.bytes());
    let frame = Frame::new(None, LinkType::LOOP, bytes).unwrap();
    let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());
    assert!(scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).is_err());
}

#[test]
fn scrub_pseudonymizes_arp_sender_and_target_addresses() {
    let sender_mac = [2, 0, 0, 0, 0, 8];
    let mut arp = vec![0_u8; 28];
    arp[0..2].copy_from_slice(&1_u16.to_be_bytes());
    arp[2..4].copy_from_slice(&0x0800_u16.to_be_bytes());
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&1_u16.to_be_bytes());
    arp[8..14].copy_from_slice(&sender_mac);
    arp[14..18].copy_from_slice(&V4_SOURCE);
    arp[24..28].copy_from_slice(&V4_DESTINATION);
    let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());

    let mut ethernet = Vec::new();
    ethernet.extend_from_slice(&[0xff; 6]);
    ethernet.extend_from_slice(&sender_mac);
    ethernet.extend_from_slice(&0x0806_u16.to_be_bytes());
    ethernet.extend_from_slice(&arp);
    let frame = Frame::new(None, LinkType::ETHERNET, ethernet).unwrap();
    let scrubbed = scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).unwrap();
    assert_eq!(&scrubbed.bytes()[6..12], &[2, 0, 0, 0, 0, 1]);
    assert_eq!(&scrubbed.bytes()[22..28], &[2, 0, 0, 0, 0, 1]);
    assert_eq!(&scrubbed.bytes()[28..32], &[10, 0, 0, 1]);
    assert_eq!(&scrubbed.bytes()[32..38], &[0; 6]);
    assert_eq!(&scrubbed.bytes()[38..42], &[10, 0, 0, 2]);

    let mut sll = vec![0_u8; 16];
    sll[4..6].copy_from_slice(&6_u16.to_be_bytes());
    sll[6..12].copy_from_slice(&sender_mac);
    sll[14..16].copy_from_slice(&0x0806_u16.to_be_bytes());
    sll.extend_from_slice(&arp);
    let frame = Frame::new(None, LinkType::LINUX_SLL, sll).unwrap();
    let scrubbed = scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).unwrap();
    assert_eq!(&scrubbed.bytes()[6..12], &[2, 0, 0, 0, 0, 1]);
    assert_eq!(&scrubbed.bytes()[24..30], &[2, 0, 0, 0, 0, 1]);
    assert_eq!(&scrubbed.bytes()[30..34], &[10, 0, 0, 1]);
    assert_eq!(&scrubbed.bytes()[40..44], &[10, 0, 0, 2]);
}

#[test]
fn scrub_refuses_malformed_fragment_to_routing_chain() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[2, 0, 0, 0, 0, 2]);
    bytes.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(&0x86dd_u16.to_be_bytes());
    let mut ip = vec![0_u8; 64];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&40_u16.to_be_bytes());
    ip[6] = 44;
    ip[7] = 64;
    ip[8..24].copy_from_slice(&V6_SOURCE);
    ip[24..40].copy_from_slice(&V6_DESTINATION);
    ip[40] = 43;
    ip[43] = 1;
    ip[44..48].copy_from_slice(&7_u32.to_be_bytes());
    ip[48] = 17;
    ip[49] = 2;
    ip[51] = 1;
    ip[56..64].copy_from_slice(&V6_SOURCE[..8]);
    bytes.extend_from_slice(&ip);
    let frame = Frame::new(None, LinkType::ETHERNET, bytes).unwrap();
    let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());
    assert!(scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).is_err());
}

#[test]
fn scrub_refuses_incomplete_ethernet_headers() {
    let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());
    for bytes in [
        vec![2, 0, 0, 0, 0, 9],
        vec![2, 0, 0, 0, 0, 9, 2, 0, 0, 0, 0, 8],
        vec![2, 0, 0, 0, 0, 9, 2, 0, 0, 0, 0, 8, 0x81, 0x00, 0, 1],
    ] {
        let frame = Frame::new(None, LinkType::ETHERNET, bytes).unwrap();
        assert!(
            scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).is_err(),
            "incomplete Ethernet header was published: {:02x?}",
            frame.bytes()
        );
    }
}

#[test]
fn scrub_drops_all_interface_option_metadata() {
    let options = [0_u16, 1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 15, 65_000]
        .into_iter()
        .map(|code| capture_file::PcapNgOption {
            code,
            value: bytes::Bytes::from_static(b"sensitive interface detail"),
        })
        .collect();
    assert!(scrub_interface_options(options).is_empty());
}

#[test]
fn pseudonyms_are_stable_sequential_and_preserve_special_addresses() {
    let mut names = Pseudonyms::default();
    let one: IpAddr = "198.51.100.9".parse().unwrap();
    let two: IpAddr = "198.51.100.10".parse().unwrap();
    assert_eq!(names.ip(one).to_string(), "10.0.0.1");
    assert_eq!(names.ip(one).to_string(), "10.0.0.1");
    assert_eq!(names.ip(two).to_string(), "10.0.0.2");
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(names.ip(loopback), loopback);
    assert_eq!(names.mac([1, 2, 3, 4, 5, 6]), [1, 2, 3, 4, 5, 6]);
    assert_eq!(names.mac([2, 2, 3, 4, 5, 6]), [2, 0, 0, 0, 0, 1]);
    assert_eq!(names.mac([2, 2, 3, 4, 5, 6]), [2, 0, 0, 0, 0, 1]);
}
