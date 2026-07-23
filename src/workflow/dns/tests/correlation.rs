// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn correlation_requires_exact_reverse_tuple_checksum_and_dns_identity() {
    let server = Ipv4Addr::new(10, 0, 0, 53);
    let client = Ipv4Addr::new(10, 0, 0, 2);
    let query = encode_dns_query("www.example", DnsQueryType::A, 42, true).unwrap();
    let probe = DnsProbe {
        attempt: 1,
        server_address: IpAddr::V4(server),
        server_port: 53,
        source_port: 50_000,
        transaction_id: 42,
        query_name: "www.example.".to_owned(),
        query_type: DnsQueryType::A,
        query,
    };
    let mut sent = Packet::new();
    sent.push(Ipv4 {
        source: client,
        destination: server,
        ..Ipv4::default()
    })
    .push(Udp {
        source_port: 50_000,
        destination_port: 53,
        ..Udp::default()
    })
    .push(Raw::new(Bytes::new()));
    let response_bytes = fixture_response(
        42,
        0,
        "www.example",
        DnsQueryType::A,
        &[FixtureRecord::in_class(
            "www.example",
            1,
            vec![192, 0, 2, 5],
        )],
        &[],
        &[],
    );
    let decoded = |source: Ipv4Addr, transaction_id: u16, diagnostics: Vec<Diagnostic>| {
        let mut bytes = response_bytes.clone();
        bytes[..2].copy_from_slice(&transaction_id.to_be_bytes());
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source,
                destination: client,
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: 53,
                destination_port: 50_000,
                ..Udp::default()
            })
            .push(Raw::new(bytes.clone()));
        DecodedPacket {
            packet,
            original: Bytes::from(bytes.clone()),
            frame: Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap(),
            layout: crate::packet::layout::PacketLayout::default(),
            diagnostics,
        }
    };
    let registry = default_registry().unwrap();

    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &decoded(server, 42, Vec::new()),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::Response(_))
    ));
    let mut renamed_probe = probe.clone();
    renamed_probe.query_name = "api.example.".to_owned();
    assert!(matches!(
        classify_dns_response(
            &registry,
            &renamed_probe,
            &sent,
            &decoded(server, 42, Vec::new()),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::Unrelated { .. })
    ));
    let mut retyped_probe = probe.clone();
    retyped_probe.query_type = DnsQueryType::Aaaa;
    assert!(matches!(
        classify_dns_response(
            &registry,
            &retyped_probe,
            &sent,
            &decoded(server, 42, Vec::new()),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::Unrelated { .. })
    ));
    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &decoded(server, 43, Vec::new()),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::Unrelated { .. })
    ));
    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &decoded(
                server,
                42,
                vec![Diagnostic::error("udp.checksum", "invalid checksum")],
            ),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::DecodeFailure { .. })
    ));
    assert!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &decoded(Ipv4Addr::new(10, 0, 0, 99), 42, Vec::new()),
            DnsLimits::default(),
        )
        .is_none()
    );

    let server_v6: Ipv6Addr = "fd00::53".parse().unwrap();
    let client_v6: Ipv6Addr = "fd00::2".parse().unwrap();
    let query_v6 = encode_dns_query("www.example", DnsQueryType::A, 44, true).unwrap();
    let probe_v6 = DnsProbe {
        attempt: 1,
        server_address: IpAddr::V6(server_v6),
        server_port: 53,
        source_port: 50_001,
        transaction_id: 44,
        query_name: "www.example.".to_owned(),
        query_type: DnsQueryType::A,
        query: query_v6,
    };
    let mut sent_v6 = Packet::new();
    sent_v6
        .push(Ipv6 {
            source: client_v6,
            destination: server_v6,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 50_001,
            destination_port: 53,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::new()));
    let response_v6 = fixture_response(
        44,
        0,
        "www.example",
        DnsQueryType::A,
        &[FixtureRecord::in_class(
            "www.example",
            1,
            vec![192, 0, 2, 44],
        )],
        &[],
        &[],
    );
    let mut response_packet_v6 = Packet::new();
    response_packet_v6
        .push(Ipv6 {
            source: server_v6,
            destination: client_v6,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 53,
            destination_port: 50_001,
            ..Udp::default()
        })
        .push(Raw::new(response_v6.clone()));
    let decoded_v6 = DecodedPacket {
        packet: response_packet_v6,
        original: Bytes::from(response_v6.clone()),
        frame: Frame::new(UNIX_EPOCH, LinkType::RAW, response_v6).unwrap(),
        layout: crate::packet::layout::PacketLayout::default(),
        diagnostics: Vec::new(),
    };
    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe_v6,
            &sent_v6,
            &decoded_v6,
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::Response(_))
    ));
    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &quoted_icmp_time_exceeded(&sent, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254))),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::NetworkFailure { reason })
            if reason == "ICMPv4 time exceeded before reaching the endpoint"
    ));
    let mut corrupt_icmp =
        quoted_icmp_time_exceeded(&sent, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)));
    corrupt_icmp
        .diagnostics
        .push(Diagnostic::error("icmpv4.checksum", "invalid checksum"));
    assert!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &corrupt_icmp,
            DnsLimits::default(),
        )
        .is_none()
    );

    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe_v6,
            &sent_v6,
            &quoted_icmp_time_exceeded(&sent_v6, IpAddr::V6("fd00::fe".parse().unwrap())),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::NetworkFailure { reason })
            if reason == "ICMPv6 time exceeded before reaching the endpoint"
    ));
}

fn quoted_icmp_time_exceeded(request: &Packet, responder: IpAddr) -> DecodedPacket {
    let udp = request.get::<Udp>().unwrap();
    let (packet, bytes) = match responder {
        IpAddr::V4(responder) => {
            let network = request.get::<Ipv4>().unwrap();
            let mut quote = vec![0_u8; 28];
            quote[0] = 0x45;
            quote[2..4].copy_from_slice(&28_u16.to_be_bytes());
            quote[9] = 17;
            quote[12..16].copy_from_slice(&network.source.octets());
            quote[16..20].copy_from_slice(&network.destination.octets());
            quote[20..22].copy_from_slice(&udp.source_port.to_be_bytes());
            quote[22..24].copy_from_slice(&udp.destination_port.to_be_bytes());
            let mut body = vec![0_u8; 4];
            body.extend(quote);
            let mut packet = Packet::new();
            packet
                .push(Ipv4 {
                    source: responder,
                    destination: network.source,
                    ..Ipv4::default()
                })
                .push(Icmpv4 {
                    icmp_type: 11,
                    body: body.into(),
                    ..Icmpv4::default()
                });
            (packet, Bytes::from_static(&[0x45]))
        }
        IpAddr::V6(responder) => {
            let network = request.get::<Ipv6>().unwrap();
            let mut quote = vec![0_u8; 48];
            quote[0] = 0x60;
            quote[4..6].copy_from_slice(&8_u16.to_be_bytes());
            quote[6] = 17;
            quote[8..24].copy_from_slice(&network.source.octets());
            quote[24..40].copy_from_slice(&network.destination.octets());
            quote[40..42].copy_from_slice(&udp.source_port.to_be_bytes());
            quote[42..44].copy_from_slice(&udp.destination_port.to_be_bytes());
            let mut body = vec![0_u8; 4];
            body.extend(quote);
            let mut packet = Packet::new();
            packet
                .push(Ipv6 {
                    source: responder,
                    destination: network.source,
                    ..Ipv6::default()
                })
                .push(Icmpv6 {
                    icmp_type: 3,
                    body: body.into(),
                    ..Icmpv6::default()
                });
            (packet, Bytes::from_static(&[0x60]))
        }
    };
    DecodedPacket {
        packet,
        original: bytes.clone(),
        frame: Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap(),
        layout: crate::packet::layout::PacketLayout::default(),
        diagnostics: Vec::new(),
    }
}
