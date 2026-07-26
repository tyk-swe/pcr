// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn tcp_direct_matcher_classifies_replies_and_rejects_bad_integrity() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 2);
    let tcp_request = tcp_packet(local, remote, 50_000, 443, Tcp::SYN);

    let syn_ack = decoded(
        tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK),
        Vec::new(),
    );
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Tcp, &tcp_request, &syn_ack)
            .unwrap()
            .classification,
        ScanClassification::Open
    );
    let mut bad_ack_packet = tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK);
    bad_ack_packet.get_mut::<Tcp>().unwrap().acknowledgment = 99;
    assert!(
        classify_scan_response(
            &registry,
            ScanTransport::Tcp,
            &tcp_request,
            &decoded(bad_ack_packet, Vec::new()),
        )
        .is_none()
    );
    let reset = decoded(
        tcp_packet(remote, local, 443, 50_000, Tcp::RST | Tcp::ACK),
        Vec::new(),
    );
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Tcp, &tcp_request, &reset)
            .unwrap()
            .classification,
        ScanClassification::Closed
    );
    let inconclusive = decoded(tcp_packet(remote, local, 443, 50_000, Tcp::ACK), Vec::new());
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Tcp, &tcp_request, &inconclusive)
            .unwrap()
            .classification,
        ScanClassification::Unknown
    );
    let corrupt = decoded(
        tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK),
        vec![Diagnostic::warning("tcp.checksum", "invalid checksum")],
    );
    assert!(
        classify_scan_response(&registry, ScanTransport::Tcp, &tcp_request, &corrupt).is_none()
    );
    assert!(
        classify_scan_response(
            &registry,
            ScanTransport::Tcp,
            &tcp_request,
            &decoded(
                tcp_packet(remote, local, 443, 50_001, Tcp::SYN | Tcp::ACK),
                Vec::new(),
            ),
        )
        .is_none()
    );
}

#[test]
fn udp_direct_matcher_classifies_reply_as_open() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 2);
    let udp_request = udp_packet(local, remote, 53_000, 53);
    let udp_response = decoded(udp_packet(remote, local, 53, 53_000), Vec::new());
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Udp, &udp_request, &udp_response)
            .unwrap()
            .classification,
        ScanClassification::Open
    );
    assert!(
        classify_scan_response(
            &registry,
            ScanTransport::Udp,
            &udp_request,
            &decoded(udp_packet(remote, local, 53, 53_001), Vec::new()),
        )
        .is_none()
    );
}

#[test]
fn icmp_direct_matcher_classifies_matching_echo_reply_as_open() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 2);
    let mut echo_request = Packet::new();
    echo_request
        .push(Ipv4 {
            source: local,
            destination: remote,
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            body: Bytes::from_static(&[0x50, 0x43, 0, 7]),
            ..Icmpv4::default()
        });
    let mut echo_reply = Packet::new();
    echo_reply
        .push(Ipv4 {
            source: remote,
            destination: local,
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            icmp_type: 0,
            body: Bytes::from_static(&[0x50, 0x43, 0, 7]),
            ..Icmpv4::default()
        });
    assert_eq!(
        classify_scan_response(
            &registry,
            ScanTransport::Icmp,
            &echo_request,
            &decoded(echo_reply.clone(), Vec::new()),
        )
        .unwrap()
        .classification,
        ScanClassification::Open
    );
    echo_reply.get_mut::<Icmpv4>().unwrap().body = Bytes::from_static(&[0x50, 0x43, 0, 8]);
    assert!(
        classify_scan_response(
            &registry,
            ScanTransport::Icmp,
            &echo_request,
            &decoded(echo_reply, Vec::new()),
        )
        .is_none()
    );
}

#[test]
fn tunneled_direct_reply_reports_the_inner_responder() {
    let registry = default_registry().unwrap();
    let outer_source: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let outer_destination: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let inner_source: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let inner_destination: Ipv6Addr = "2001:db8:1::2".parse().unwrap();
    let mut request = Packet::new();
    request
        .push(Ipv6 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv6::default()
        })
        .push(Ipv6 {
            source: inner_source,
            destination: inner_destination,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 50_000,
            destination_port: 53,
            ..Udp::default()
        });
    let mut reply = Packet::new();
    reply
        .push(Ipv6 {
            source: "2001:db8:ffff::1".parse().unwrap(),
            destination: "2001:db8:ffff::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Ipv6 {
            source: inner_destination,
            destination: inner_source,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 53,
            destination_port: 50_000,
            ..Udp::default()
        });

    let classification = classify_scan_response(
        &registry,
        ScanTransport::Udp,
        &request,
        &decoded(reply, Vec::new()),
    )
    .unwrap();

    assert_eq!(classification.classification, ScanClassification::Open);
    assert_eq!(classification.responder, IpAddr::V6(inner_destination));
}

fn ipv4_quote(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, payload: [u8; 8]) -> Vec<u8> {
    let mut quote = vec![0_u8; 28];
    quote[0] = 0x45;
    quote[2..4].copy_from_slice(&28_u16.to_be_bytes());
    quote[8] = 63;
    quote[9] = protocol;
    quote[12..16].copy_from_slice(&source.octets());
    quote[16..20].copy_from_slice(&destination.octets());
    quote[20..28].copy_from_slice(&payload);
    quote
}

fn icmpv4_error(
    router: Ipv4Addr,
    local: Ipv4Addr,
    icmp_type: u8,
    code: u8,
    quote: Vec<u8>,
) -> DecodedPacket {
    let mut body = vec![0_u8; 4];
    body.extend(quote);
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: router,
            destination: local,
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            icmp_type,
            code,
            body: Bytes::from(body),
            ..Icmpv4::default()
        });
    decoded(packet, Vec::new())
}

#[test]
fn quoted_icmp_errors_require_the_exact_probe_tuple_and_classify_semantics() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 2);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let request = udp_packet(local, remote, 53_000, 161);
    let ports = [
        (53_000_u16 >> 8) as u8,
        53_000_u16 as u8,
        0,
        161,
        0,
        8,
        0,
        0,
    ];

    let closed = icmpv4_error(router, local, 3, 3, ipv4_quote(local, remote, 17, ports));
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Udp, &request, &closed)
            .unwrap()
            .classification,
        ScanClassification::Closed
    );
    let filtered = icmpv4_error(router, local, 3, 13, ipv4_quote(local, remote, 17, ports));
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Udp, &request, &filtered)
            .unwrap()
            .classification,
        ScanClassification::Filtered
    );
    let unreachable = icmpv4_error(router, local, 3, 1, ipv4_quote(local, remote, 17, ports));
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Udp, &request, &unreachable)
            .unwrap()
            .classification,
        ScanClassification::Unreachable
    );
    let unrelated = icmpv4_error(
        router,
        local,
        3,
        3,
        ipv4_quote(local, Ipv4Addr::new(10, 0, 0, 99), 17, ports),
    );
    assert!(classify_scan_response(&registry, ScanTransport::Udp, &request, &unrelated).is_none());
}

fn ipv6_quote(source: Ipv6Addr, destination: Ipv6Addr, protocol: u8, payload: [u8; 8]) -> Vec<u8> {
    let mut quote = vec![0_u8; 48];
    quote[0] = 0x60;
    quote[4..6].copy_from_slice(&8_u16.to_be_bytes());
    quote[6] = protocol;
    quote[7] = 63;
    quote[8..24].copy_from_slice(&source.octets());
    quote[24..40].copy_from_slice(&destination.octets());
    quote[40..48].copy_from_slice(&payload);
    quote
}

#[test]
fn ipv6_icmp_echo_and_quoted_udp_modes_are_correlated() {
    let registry = default_registry().unwrap();
    let local: Ipv6Addr = "fd00::1".parse().unwrap();
    let remote: Ipv6Addr = "fd00::2".parse().unwrap();
    let router: Ipv6Addr = "fd00::fe".parse().unwrap();

    let mut echo_request = Packet::new();
    echo_request
        .push(Ipv6 {
            source: local,
            destination: remote,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            body: Bytes::from_static(&[0x50, 0x43, 0, 9]),
            ..Icmpv6::default()
        });
    let mut echo_reply = Packet::new();
    echo_reply
        .push(Ipv6 {
            source: remote,
            destination: local,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            icmp_type: 129,
            body: Bytes::from_static(&[0x50, 0x43, 0, 9]),
            ..Icmpv6::default()
        });
    assert_eq!(
        classify_scan_response(
            &registry,
            ScanTransport::Icmp,
            &echo_request,
            &decoded(echo_reply, Vec::new()),
        )
        .unwrap()
        .classification,
        ScanClassification::Open
    );

    let mut udp_request = Packet::new();
    udp_request
        .push(Ipv6 {
            source: local,
            destination: remote,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 53_000,
            destination_port: 53,
            ..Udp::default()
        });
    let payload = [0xcf, 0x08, 0, 53, 0, 8, 0, 0];
    let mut body = vec![0_u8; 4];
    body.extend(ipv6_quote(local, remote, 17, payload));
    let mut error = Packet::new();
    error
        .push(Ipv6 {
            source: router,
            destination: local,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            icmp_type: 1,
            code: 4,
            body: Bytes::from(body),
            ..Icmpv6::default()
        });
    assert_eq!(
        classify_scan_response(
            &registry,
            ScanTransport::Udp,
            &udp_request,
            &decoded(error, Vec::new()),
        )
        .unwrap()
        .classification,
        ScanClassification::Closed
    );
}
