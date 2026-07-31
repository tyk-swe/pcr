// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};

use bytes::Bytes;
use packetcraftr_packet::{
    Packet, diagnostic::DiagnosticSeverity, filter::Options as FilterOptions, layer::Raw,
};
use packetcraftr_protocol::{
    icmp::{Icmpv4, Icmpv6},
    network::{Ipv4, Ipv6},
    transport::{Tcp, Udp},
};

use super::*;

fn request(source: IpAddr, destination: IpAddr, tcp: bool) -> Packet {
    let mut packet = Packet::new();
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            packet.push(Ipv4 {
                source,
                destination,
                ..Ipv4::default()
            });
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            packet.push(Ipv6 {
                source,
                destination,
                ..Ipv6::default()
            });
        }
        _ => unreachable!("test endpoints use one IP family"),
    }
    if tcp {
        packet.push(Tcp {
            source_port: 40_000,
            destination_port: 443,
            sequence: 7,
            flags: Tcp::SYN,
            ..Tcp::default()
        });
    } else {
        packet
            .push(Udp {
                source_port: 40_000,
                destination_port: 33434,
                ..Udp::default()
            })
            .push(Raw::new(Bytes::from_static(b"probe")));
    }
    packet
}

fn error_packet(
    responder: IpAddr,
    receiver: IpAddr,
    quoted_source: IpAddr,
    quoted_destination: IpAddr,
    protocol: u8,
    icmp_type: u8,
    code: u8,
) -> Packet {
    let mut quote = match (quoted_source, quoted_destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let mut quote = vec![0_u8; 28];
            quote[0] = 0x45;
            quote[2..4].copy_from_slice(&28_u16.to_be_bytes());
            quote[9] = protocol;
            quote[12..16].copy_from_slice(&source.octets());
            quote[16..20].copy_from_slice(&destination.octets());
            quote
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let mut quote = vec![0_u8; 48];
            quote[0] = 0x60;
            quote[4..6].copy_from_slice(&8_u16.to_be_bytes());
            quote[6] = protocol;
            quote[8..24].copy_from_slice(&source.octets());
            quote[24..40].copy_from_slice(&destination.octets());
            quote
        }
        _ => unreachable!("test endpoints use one IP family"),
    };
    let transport = if quoted_source.is_ipv4() { 20 } else { 40 };
    quote[transport..transport + 2].copy_from_slice(&40_000_u16.to_be_bytes());
    quote[transport + 2..transport + 4]
        .copy_from_slice(&(if protocol == 6 { 443_u16 } else { 33434_u16 }).to_be_bytes());
    if protocol == 6 {
        quote[transport + 4..transport + 8].copy_from_slice(&7_u32.to_be_bytes());
    }
    let mut body = vec![0_u8; 4];
    body.extend(quote);

    let mut packet = Packet::new();
    match (responder, receiver) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            packet
                .push(Ipv4 {
                    source,
                    destination,
                    ..Ipv4::default()
                })
                .push(Icmpv4 {
                    icmp_type,
                    code,
                    body: body.into(),
                    ..Icmpv4::default()
                });
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            packet
                .push(Ipv6 {
                    source,
                    destination,
                    ..Ipv6::default()
                })
                .push(Icmpv6 {
                    icmp_type,
                    code,
                    body: body.into(),
                    ..Icmpv6::default()
                });
        }
        _ => unreachable!("test endpoints use one IP family"),
    }
    packet
}

fn icmp_findings(packets: Vec<Packet>, filter: Option<&Filter>) -> Vec<expert::Finding> {
    expert_findings(
        &mut capture(packets),
        &AnalysisOptions {
            filter,
            ..AnalysisOptions::default()
        },
    )
    .into_iter()
    .filter(|finding| finding.code.starts_with("icmp."))
    .collect()
}

#[test]
fn ipv4_udp_time_exceeded_and_tcp_destination_unreachable_correlate() {
    let udp_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let tcp_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
    let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
    let router = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let findings = icmp_findings(
        vec![
            request(udp_source, destination, false),
            error_packet(router, udp_source, udp_source, destination, 17, 11, 0),
            request(tcp_source, destination, true),
            error_packet(router, tcp_source, tcp_source, destination, 6, 3, 1),
        ],
        None,
    );
    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.code.as_str(), finding.stream))
            .collect::<Vec<_>>(),
        [
            (
                "icmp.time_exceeded",
                Some(expert::StreamRef {
                    transport: expert::StreamTransport::Udp,
                    index: 0,
                }),
            ),
            (
                "icmp.destination_unreachable",
                Some(expert::StreamRef {
                    transport: expert::StreamTransport::Tcp,
                    index: 0,
                }),
            ),
        ]
    );
    assert_eq!(findings[0].number, 2);
    assert_eq!(findings[1].number, 4);
}

#[test]
fn ipv6_port_unreachable_and_administratively_prohibited_are_classified() {
    let udp_source = IpAddr::V6("2001:db8::1".parse().unwrap());
    let tcp_source = IpAddr::V6("2001:db8::3".parse().unwrap());
    let destination = IpAddr::V6("2001:db8::2".parse().unwrap());
    let router = IpAddr::V6("2001:db8::ff".parse().unwrap());
    let findings = icmp_findings(
        vec![
            request(udp_source, destination, false),
            error_packet(router, udp_source, udp_source, destination, 17, 1, 4),
            request(tcp_source, destination, true),
            error_packet(router, tcp_source, tcp_source, destination, 6, 1, 1),
        ],
        None,
    );
    assert_eq!(findings[0].code, "icmp.port_unreachable");
    assert_eq!(findings[0].severity, DiagnosticSeverity::Info);
    assert_eq!(
        findings[0].stream.unwrap().transport,
        expert::StreamTransport::Udp
    );
    assert_eq!(findings[1].code, "icmp.administratively_prohibited");
    assert_eq!(findings[1].severity, DiagnosticSeverity::Warning);
    assert_eq!(
        findings[1].stream.unwrap().transport,
        expert::StreamTransport::Tcp
    );
}

#[test]
fn display_filter_keeps_capture_global_stream_correlation() {
    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
    let router = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let registry = registry();
    let filter = Filter::compile("icmp", &registry, FilterOptions::default()).unwrap();
    let findings = icmp_findings(
        vec![
            request(source, destination, false),
            error_packet(router, source, source, destination, 17, 11, 0),
        ],
        Some(&filter),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].stream,
        Some(expert::StreamRef {
            transport: expert::StreamTransport::Udp,
            index: 0,
        })
    );
}

#[test]
fn unknown_flow_still_explains_error_without_fabricating_stream() {
    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
    let router = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let findings = icmp_findings(
        vec![error_packet(router, source, source, destination, 17, 3, 3)],
        None,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, "icmp.port_unreachable");
    assert_eq!(findings[0].stream, None);
    assert!(findings[0].message.contains("203.0.113.1"));
    assert!(findings[0].message.contains("192.0.2.1:40000"));
}

#[test]
fn truncated_malformed_noninitial_opaque_and_unrelated_quotes_are_rejected() {
    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
    let router = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let mut truncated = error_packet(router, source, source, destination, 17, 11, 0);
    truncated.get_mut::<Icmpv4>().unwrap().body.truncate(20);
    let mut malformed = error_packet(router, source, source, destination, 17, 11, 0);
    let mut body = malformed.get::<Icmpv4>().unwrap().body.to_vec();
    body[4] = 0x44;
    malformed.get_mut::<Icmpv4>().unwrap().body = body.into();
    let mut noninitial_v4 = error_packet(router, source, source, destination, 17, 11, 0);
    let mut body = noninitial_v4.get::<Icmpv4>().unwrap().body.to_vec();
    body[10..12].copy_from_slice(&1_u16.to_be_bytes());
    noninitial_v4.get_mut::<Icmpv4>().unwrap().body = body.into();
    let opaque = error_packet(router, source, source, destination, 132, 3, 1);
    let unrelated = error_packet(
        router,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
        source,
        destination,
        17,
        11,
        0,
    );

    let source_v6 = IpAddr::V6("2001:db8::1".parse().unwrap());
    let destination_v6 = IpAddr::V6("2001:db8::2".parse().unwrap());
    let router_v6 = IpAddr::V6("2001:db8::ff".parse().unwrap());
    let mut noninitial_v6 = error_packet(router_v6, source_v6, source_v6, destination_v6, 17, 3, 0);
    let old = noninitial_v6.get::<Icmpv6>().unwrap().body.to_vec();
    let mut body = old[..44].to_vec();
    body[10] = 44;
    body[8..10].copy_from_slice(&16_u16.to_be_bytes());
    body.extend_from_slice(&[17, 0, 0, 8, 0, 0, 0, 1]);
    body.extend_from_slice(&old[44..]);
    noninitial_v6.get_mut::<Icmpv6>().unwrap().body = body.into();

    assert!(
        icmp_findings(
            vec![
                truncated,
                malformed,
                noninitial_v4,
                noninitial_v6,
                opaque,
                unrelated,
            ],
            None,
        )
        .is_empty()
    );
}
