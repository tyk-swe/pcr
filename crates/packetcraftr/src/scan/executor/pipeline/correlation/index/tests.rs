// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::{
    probe::Endpoint,
    scan::{Probe, SctpScan, Stage},
};
use packetcraftr_core::{
    build, codec, decode,
    field::WireValue,
    frame::{Frame, LinkType},
    layer::Raw,
    matcher::{Match, ResponseMatcher},
    protocol::{
        builtin,
        network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
        transport::{Sctp, Tcp, Udp},
    },
};
use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, SystemTime},
};

fn probe(endpoint: Endpoint, sequence: u64, ipv6: bool) -> Probe {
    Probe {
        sequence,
        stage: Stage::Scan,
        address: if ipv6 {
            "2001:db8::1".parse().unwrap()
        } else {
            Ipv4Addr::new(192, 0, 2, 1).into()
        },
        scope: None,
        endpoint,
        tcp_scan: Default::default(),
        sctp_scan: Default::default(),
        attempt: 1,
        udp_payload: Default::default(),
        udp_profile: None,
    }
}

fn built(packet: Packet) -> build::BuiltPacket {
    build::Builder::new(builtin::registry())
        .build(
            packet,
            codec::Addresses::default(),
            build::Options::default(),
        )
        .unwrap()
}

fn request(probe: &Probe) -> Packet {
    let mut packet = probe.packet();
    if let Some(ip) = packet.get_mut::<Ipv4>() {
        ip.source = Ipv4Addr::new(192, 0, 2, 254);
    }
    if let Some(ip) = packet.get_mut::<Ipv6>() {
        ip.source = "2001:db8::fe".parse().unwrap();
    }
    built(packet).packet
}

fn response_base(sent: &Packet) -> Packet {
    let mut response = Packet::new();
    if let Some(ip) = sent.get::<Ipv4>() {
        response.push(Ipv4 {
            source: ip.destination,
            destination: ip.source,
            identification: ip.identification.wrapping_add(10),
            ..Default::default()
        });
    } else {
        let ip = sent.get::<Ipv6>().unwrap();
        response.push(Ipv6 {
            source: ip.destination,
            destination: ip.source,
            flow_label: ip.flow_label.wrapping_add(10),
            ..Default::default()
        });
    }
    response
}

fn decode(packet: Packet) -> decode::DecodedPacket {
    let encoded = built(packet);
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, encoded.bytes).unwrap();
    decode::Dissector::new(builtin::registry())
        .decode(frame, decode::Options::default())
        .unwrap()
}

fn reply(probe: &Probe, sent: &Packet) -> decode::DecodedPacket {
    let mut response = response_base(sent);
    match probe.endpoint {
        Endpoint::Tcp { .. } | Endpoint::TcpAck { .. } => {
            let tcp = sent.get::<Tcp>().unwrap();
            response.push(Tcp {
                source_port: tcp.destination_port,
                destination_port: tcp.source_port,
                acknowledgment: tcp.sequence.wrapping_add(1),
                flags: Tcp::SYN | Tcp::ACK,
                ..Default::default()
            });
        }
        Endpoint::Udp { .. } => {
            let udp = sent.get::<Udp>().unwrap();
            response.push(Udp {
                source_port: udp.destination_port,
                destination_port: udp.source_port,
                ..Default::default()
            });
            response.push(Raw::new(bytes::Bytes::from_static(b"reply")));
        }
        Endpoint::Sctp { .. } => {
            let sctp = sent.get::<Sctp>().unwrap();
            response.push(Sctp {
                source_port: sctp.destination_port,
                destination_port: sctp.source_port,
                verification_tag: SctpScan::tag(probe.sequence),
                ..Default::default()
            });
            response.push(Raw::new(bytes::Bytes::from_static(&[6, 0, 0, 4])));
        }
        Endpoint::Icmp | Endpoint::IcmpTimestamp | Endpoint::IcmpNetmask => {
            if let Some(icmp) = sent.get::<Icmpv4>() {
                let icmp_type = match icmp.icmp_type {
                    8 => 0,
                    13 => 14,
                    17 => 18,
                    _ => unreachable!(),
                };
                response.push(Icmpv4 {
                    icmp_type,
                    body: icmp.body.clone(),
                    ..Default::default()
                });
            } else {
                response.push(Icmpv6 {
                    icmp_type: 129,
                    body: sent.get::<Icmpv6>().unwrap().body.clone(),
                    ..Default::default()
                });
            }
        }
        Endpoint::Ip { protocol } => {
            if let Some(ip) = response.get_mut::<Ipv4>() {
                ip.protocol = WireValue::Exact(protocol);
            }
            if let Some(ip) = response.get_mut::<Ipv6>() {
                ip.next_header = WireValue::Exact(protocol);
            }
            response.push(Raw::new(bytes::Bytes::from_static(b"payload")));
        }
    }
    decode(response)
}

fn quote(sent: &Packet, truncate: Option<usize>) -> decode::DecodedPacket {
    let mut response = response_base(sent);
    let mut bytes = built(sent.clone()).bytes;
    if let Some(limit) = truncate {
        bytes.truncate(limit);
    }
    let mut body = vec![0; 4];
    body.extend_from_slice(&bytes);
    if sent.get::<Ipv4>().is_some() {
        response.push(Icmpv4 {
            icmp_type: 11,
            body: body.into(),
            ..Default::default()
        });
    } else {
        response.push(Icmpv6 {
            icmp_type: 3,
            body: body.into(),
            ..Default::default()
        });
    }
    decode(response)
}

fn observed(
    index: &CandidateIndex,
    probes: &[Probe],
    packets: &[Packet],
    response: &decode::DecodedPacket,
    source: usize,
) -> Vec<usize> {
    index
        .lookup(source, &response.packet)
        .into_iter()
        .filter(|index| {
            super::super::observe(
                &builtin::registry(),
                &probes[*index],
                &packets[*index],
                response,
            )
            .is_some()
        })
        .collect()
}

fn conservative(
    probes: &[Probe],
    packets: &[Packet],
    response: &decode::DecodedPacket,
) -> Vec<usize> {
    probes
        .iter()
        .zip(packets)
        .enumerate()
        .filter_map(|(index, (probe, packet))| {
            super::super::observe(&builtin::registry(), probe, packet, response).map(|_| index)
        })
        .collect()
}

#[test]
fn unrelated_pending_ports_do_not_match_direct_or_quoted_replies() {
    for count in [32, 128, 512] {
        let probes = (0..count)
            .map(|n| {
                probe(
                    Endpoint::Tcp {
                        port: 1000 + n as u16,
                    },
                    n as u64,
                    false,
                )
            })
            .collect::<Vec<_>>();
        let packets = probes.iter().map(request).collect::<Vec<_>>();
        let mut index = CandidateIndex::new(1, count);
        for (n, packet) in packets.iter().enumerate() {
            index.insert(n, 0, packet, &builtin::registry()).unwrap();
        }
        for frames in [1, 8, 64] {
            for quoted in [false, true] {
                let responses = (0..frames)
                    .map(|n| {
                        let p = probe(
                            Endpoint::Tcp {
                                port: 60000 + n as u16,
                            },
                            10000 + n as u64,
                            false,
                        );
                        let sent = request(&p);
                        if quoted {
                            quote(&sent, None)
                        } else {
                            reply(&p, &sent)
                        }
                    })
                    .collect::<Vec<_>>();
                for response in &responses {
                    assert!(conservative(&probes, &packets, response).is_empty());
                }
                for response in &responses {
                    assert!(observed(&index, &probes, &packets, response, 0).is_empty());
                }
                let response = if quoted {
                    quote(&packets[count / 2], None)
                } else {
                    reply(&probes[count / 2], &packets[count / 2])
                };
                assert_eq!(
                    observed(&index, &probes, &packets, &response, 0),
                    vec![count / 2]
                );
            }
        }
    }
}

#[test]
fn direct_and_quoted_supported_families_match_the_conservative_oracle() {
    let mut probes = Vec::new();
    for ipv6 in [false, true] {
        for endpoint in [
            Endpoint::Tcp { port: 1000 },
            Endpoint::Udp { port: 1001 },
            Endpoint::Sctp { port: 1002 },
            Endpoint::Icmp,
            Endpoint::Ip { protocol: 253 },
        ] {
            probes.push(probe(endpoint, probes.len() as u64 + 1, ipv6));
        }
    }
    probes.push(probe(Endpoint::IcmpTimestamp, 30, false));
    probes.push(probe(Endpoint::IcmpNetmask, 31, false));
    let packets = probes.iter().map(request).collect::<Vec<_>>();
    let mut index = CandidateIndex::new(1, probes.len());
    for (n, packet) in packets.iter().enumerate() {
        index.insert(n, 0, packet, &builtin::registry()).unwrap();
    }
    for (probe, packet) in probes.iter().zip(&packets) {
        for response in [
            reply(probe, packet),
            quote(packet, None),
            quote(packet, Some(if probe.address.is_ipv4() { 28 } else { 48 })),
        ] {
            let expected = conservative(&probes, &packets, &response);
            // Short SCTP INIT quotes intentionally fail the authoritative
            // chunk/checksum requirements; both paths must retain that result.
            assert_eq!(observed(&index, &probes, &packets, &response, 0), expected);
        }
    }
}

#[test]
fn collisions_scopes_reuse_and_retirement_preserve_every_member() {
    let p = probe(Endpoint::Udp { port: 1000 }, 1, false);
    let sent = request(&p);
    let response = reply(&p, &sent);
    let mut index = CandidateIndex::new(2, 3);
    for (attempt, source) in [(0, 0), (1, 0), (2, 1)] {
        index
            .insert(attempt, source, &sent, &builtin::registry())
            .unwrap();
    }
    assert_eq!(index.lookup(0, &response.packet), vec![0, 1]);
    assert_eq!(index.lookup(1, &response.packet), vec![2]);
    index.remove(0);
    assert_eq!(index.lookup(0, &response.packet), vec![1]);
    index.remove(1);
    index.insert(3, 0, &sent, &builtin::registry()).unwrap();
    assert_eq!(index.lookup(0, &response.packet), vec![3]);
    index.remove(3);
    assert!(index.lookup(0, &response.packet).is_empty());
    assert_eq!(index.lookup(1, &response.packet), vec![2]);
    assert!(index.insert(2, 0, &sent, &builtin::registry()).is_err());
}

#[derive(Debug)]
struct Arbitrary;
impl ResponseMatcher for Arbitrary {
    fn matches(&self, _: &Packet, _: &Packet) -> Option<Match> {
        Some(Match::new(255))
    }
}

#[derive(Debug)]
struct ProxyCodec(&'static str);
impl codec::Codec for ProxyCodec {
    fn protocol_id(&self) -> &'static packetcraftr_core::layer::Id {
        builtin::registry().codec(self.0).unwrap().protocol_id()
    }
    fn encode(
        &self,
        layer: &dyn packetcraftr_core::layer::Layer,
        payload: &[u8],
        context: &codec::EncodeContext<'_>,
    ) -> Result<codec::Encoded, codec::Error> {
        builtin::registry()
            .codec(self.0)
            .unwrap()
            .encode(layer, payload, context)
    }
    fn decode(
        &self,
        bytes: bytes::Bytes,
        context: &codec::DecodeContext<'_>,
    ) -> Result<codec::Decoded, codec::Error> {
        builtin::registry()
            .codec(self.0)
            .unwrap()
            .decode(bytes, context)
    }
    fn make_layer(
        &self,
        fields: &std::collections::BTreeMap<String, packetcraftr_core::field::Value>,
    ) -> Result<Box<dyn packetcraftr_core::layer::Layer>, codec::Error> {
        builtin::registry()
            .codec(self.0)
            .unwrap()
            .make_layer(fields)
    }
}

#[test]
fn custom_matcher_defaults_to_scoped_conservative_lookup() {
    let mut builder = Registry::builder();
    builder.register_codec(ProxyCodec("tcp"), &[]).unwrap();
    builder.register_matcher("tcp", Arbitrary).unwrap();
    let registry = builder.build().unwrap();
    let p = probe(Endpoint::Tcp { port: 1000 }, 1, false);
    let packet = request(&p);
    let unrelated = probe(Endpoint::Tcp { port: 60000 }, 900, false);
    let response = reply(&unrelated, &request(&unrelated));
    let mut index = CandidateIndex::new(2, 2);
    index.insert(0, 0, &packet, &registry).unwrap();
    index.insert(1, 1, &packet, &registry).unwrap();
    assert_eq!(index.lookup(0, &response.packet), vec![0]);
    assert_eq!(index.lookup(1, &response.packet), vec![1]);
    assert!(super::super::observe(&registry, &p, &packet, &response).is_some());
    index.remove(0);
}

fn materialized_sent(
    packet: Packet,
    native: packetcraftr_netio::interface::Id,
) -> Arc<crate::evidence::SentPacket> {
    let encoded = built(packet);
    let path = packetcraftr_core::protocol::semantics::outer_ip_path(&encoded.packet)
        .unwrap()
        .unwrap();
    let decision = packetcraftr_netio::route::Decision {
        interface: native,
        source_mac: None,
        selected_source: Some(path.source),
        preferred_source: None,
        next_hop: None,
        selection_reason: packetcraftr_netio::route::SelectionReason::OnLink,
        destination_scope: packetcraftr_netio::route::Scope::Link,
        mtu: 1500,
        capability: packetcraftr_netio::link::Capability::Layer3,
        link_type: LinkType::RAW,
    };
    let route = crate::route::Materialized {
        plan: crate::route::Plan {
            decision,
            mode: packetcraftr_netio::link::Mode::Layer3,
            lookup_destination: Some(path.header_destination),
            final_destination: Some(path.final_destination),
            visited_destinations: path.visited_destinations,
            packet_source: Some(path.source),
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: None,
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        },
        neighbor_resolution: None,
    };
    let report =
        packetcraftr_netio::transmit::Report::committed(encoded.bytes.len(), encoded.bytes.clone());
    Arc::new(crate::evidence::SentPacket::try_new(encoded, route, report).unwrap())
}

#[test]
fn indexed_correlation_preserves_generation_freshness_deadlines_interfaces_and_late_replies() {
    let native = packetcraftr_netio::interface::Id {
        index: 1,
        name: "candidate0".to_owned(),
    };
    let wrong_native = packetcraftr_netio::interface::Id {
        index: 1,
        name: "recreated".to_owned(),
    };
    let probes = [
        probe(Endpoint::Tcp { port: 1000 }, 1, false),
        probe(Endpoint::Tcp { port: 1000 }, 2, false),
    ];
    let packets = probes.iter().map(request).collect::<Vec<_>>();
    let sent = packets
        .iter()
        .map(|packet| materialized_sent(packet.clone(), native.clone()))
        .collect::<Vec<_>>();
    let received = sent[1].timing().freshness_marker().monotonic() + Duration::from_millis(1);
    let planned = probes
        .iter()
        .map(|probe| super::super::super::Planned { probe })
        .collect::<Vec<_>>();
    let mut pending = sent
        .iter()
        .enumerate()
        .map(|(index, sent)| {
            (
                index,
                super::super::super::Pending {
                    sent: Arc::clone(sent),
                    deadline: received + Duration::from_secs(1),
                    best: None,
                    passed: Vec::new(),
                    last_response: None,
                    charge: 0,
                },
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut index = CandidateIndex::new(1, 2);
    for (n, packet) in packets.iter().enumerate() {
        index.insert(n, 0, packet, &builtin::registry()).unwrap();
    }
    let response = reply(&probes[1], &packets[1]);
    let possible = index.lookup(0, &response.packet);
    assert_eq!(
        possible,
        vec![0, 1],
        "port collision retains both generations"
    );
    let observe = |pending: &_, received, interface: &_| {
        super::super::indexed_candidates(
            &possible,
            pending,
            |index| planned.get(index).map(|planned| planned.probe),
            &builtin::registry(),
            &response,
            interface,
            received,
        )
        .into_iter()
        .map(|(index, _)| index)
        .collect::<Vec<_>>()
    };
    let expected = super::super::candidates(
        &pending,
        &planned,
        &builtin::registry(),
        &response,
        &native,
        received,
    )
    .into_iter()
    .map(|(index, _)| index)
    .collect::<Vec<_>>();
    assert_eq!(observe(&pending, received, &native), expected);
    assert_eq!(expected, vec![1]);
    assert!(
        observe(
            &pending,
            sent[0].timing().freshness_marker().monotonic() - Duration::from_nanos(1),
            &native
        )
        .is_empty()
    );
    assert!(observe(&pending, received, &wrong_native).is_empty());
    pending.get_mut(&1).unwrap().deadline = received - Duration::from_nanos(1);
    assert!(observe(&pending, received, &native).is_empty());
    let expired = super::super::indexed_settled(
        &possible,
        |n| {
            pending
                .get(&n)
                .filter(|entry| received > entry.deadline)
                .map(|entry| &entry.sent)
        },
        |index| planned.get(index).map(|planned| planned.probe),
        &builtin::registry(),
        &response,
        &native,
        received,
    );
    let expected = super::super::settled(
        pending
            .iter()
            .filter(|(_, entry)| received > entry.deadline)
            .map(|(index, entry)| (*index, &entry.sent)),
        &planned,
        &builtin::registry(),
        &response,
        &native,
        received,
    );
    assert_eq!(expired, expected);
    assert_eq!(expected, vec![1]);
    // Retaining a settled attempt for late/duplicate evidence preserves its
    // index until the actual recent-cache eviction, then removes it completely.
    let settled = pending.remove(&1).unwrap().sent;
    let late = super::super::indexed_settled(
        &possible,
        |n| (n == 1).then_some(&settled),
        |index| planned.get(index).map(|planned| planned.probe),
        &builtin::registry(),
        &response,
        &native,
        received,
    );
    assert_eq!(late, vec![1]);
    index.remove(1);
    assert_eq!(index.lookup(0, &response.packet), vec![0]);
    index.remove(0);
    assert!(index.lookup(0, &response.packet).is_empty());
}

#[test]
fn ipv6_extension_ip_replies_and_truncated_or_bad_integrity_packets_use_the_same_oracle() {
    let p = probe(Endpoint::Ip { protocol: 0 }, 1, true);
    let sent = request(&p);
    let mut response = response_base(&sent);
    response.push(packetcraftr_core::protocol::network::HopByHop::default());
    response.push(Udp {
        source_port: 1000,
        destination_port: 1001,
        ..Default::default()
    });
    response.push(Raw::new(bytes::Bytes::from_static(b"reply")));
    let response = decode(response);
    let mut index = CandidateIndex::new(1, 1);
    index.insert(0, 0, &sent, &builtin::registry()).unwrap();
    assert_eq!(
        observed(
            &index,
            std::slice::from_ref(&p),
            std::slice::from_ref(&sent),
            &response,
            0
        ),
        vec![0]
    );
    let p = probe(Endpoint::Tcp { port: 1000 }, 2, false);
    let sent = request(&p);
    let mut index = CandidateIndex::new(1, 1);
    index.insert(0, 0, &sent, &builtin::registry()).unwrap();
    let correct = reply(&p, &sent);
    for length in [0, 1, 19, 23, 39] {
        let bytes = correct
            .frame
            .bytes()
            .slice(..length.min(correct.frame.bytes().len()));
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).unwrap();
        if let Ok(decoded) =
            decode::Dissector::new(builtin::registry()).decode(frame, decode::Options::default())
        {
            assert_eq!(
                observed(
                    &index,
                    std::slice::from_ref(&p),
                    std::slice::from_ref(&sent),
                    &decoded,
                    0
                ),
                conservative(
                    std::slice::from_ref(&p),
                    std::slice::from_ref(&sent),
                    &decoded
                )
            );
        }
    }
    let mut corrupt = correct.frame.bytes().to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, corrupt).unwrap();
    let decoded = decode::Dissector::new(builtin::registry())
        .decode(frame, decode::Options::default())
        .unwrap();
    assert!(observed(&index, &[p], &[sent], &decoded, 0).is_empty());
}

#[test]
fn unknown_custom_decoded_identity_and_unrecognized_tunnels_use_conservative_fallback() {
    let mut builder = Registry::builder();
    builder.register_codec(ProxyCodec("ipv4"), &[]).unwrap();
    builder.register_matcher("ipv4", Arbitrary).unwrap();
    let registry = builder.build().unwrap();
    let p = probe(Endpoint::Ip { protocol: 253 }, 1, false);
    let sent = request(&p);
    let mut response = reply(&p, &sent);
    // Custom decoders need not materialize the header discriminator as Exact.
    // Valid outer addresses do not justify discarding their fallback bucket.
    response.packet.get_mut::<Ipv4>().unwrap().protocol = WireValue::Auto;
    let mut index = CandidateIndex::new(1, 1);
    index.insert(0, 0, &sent, &registry).unwrap();
    assert_eq!(index.lookup(0, &response.packet), vec![0]);
    assert!(super::super::observe(&registry, &p, &sent, &response).is_some());

    let mut unrecognized = request(&probe(Endpoint::Tcp { port: 1000 }, 2, false));
    unrecognized
        .insert(1, packetcraftr_core::protocol::tunnel::Gre::default())
        .unwrap();
    let mut index = CandidateIndex::new(1, 1);
    index
        .insert(0, 0, &unrecognized, &builtin::registry())
        .unwrap();
    assert_eq!(
        index.scopes[0].fallback.iter().copied().collect::<Vec<_>>(),
        vec![0]
    );
}

#[test]
fn encapsulated_udp_probe_preserves_inner_matching_and_outer_quoted_identity() {
    use packetcraftr_core::protocol::{link::Ethernet, tunnel::Vxlan};
    let mut p = probe(Endpoint::Udp { port: 4789 }, 7, false);
    let mut payload = Packet::new();
    payload.push(Vxlan {
        vni: 7,
        ..Default::default()
    });
    payload.push(Ethernet::default());
    payload.push(Ipv4 {
        source: Ipv4Addr::new(10, 1, 0, 1),
        destination: Ipv4Addr::new(10, 1, 0, 2),
        ..Default::default()
    });
    payload.push(Tcp {
        source_port: 1234,
        destination_port: 4321,
        sequence: 77,
        flags: Tcp::SYN,
        ..Default::default()
    });
    p.udp_payload = built(payload).bytes;
    let sent = request(&p);
    assert!(sent.get::<Vxlan>().is_some());
    let mut response = response_base(&sent);
    let udp = sent.get::<Udp>().unwrap();
    response.push(Udp {
        source_port: udp.destination_port,
        destination_port: udp.source_port,
        ..Default::default()
    });
    response.push(Vxlan {
        vni: 7,
        ..Default::default()
    });
    response.push(Ethernet::default());
    response.push(Ipv4 {
        source: Ipv4Addr::new(10, 1, 0, 2),
        destination: Ipv4Addr::new(10, 1, 0, 1),
        ..Default::default()
    });
    response.push(Tcp {
        source_port: 4321,
        destination_port: 1234,
        acknowledgment: 78,
        flags: Tcp::SYN | Tcp::ACK,
        ..Default::default()
    });
    let mut index = CandidateIndex::new(1, 1);
    index.insert(0, 0, &sent, &builtin::registry()).unwrap();
    for response in [decode(response), quote(&sent, Some(28))] {
        let expected = conservative(
            std::slice::from_ref(&p),
            std::slice::from_ref(&sent),
            &response,
        );
        assert_eq!(expected, vec![0]);
        assert_eq!(
            observed(
                &index,
                std::slice::from_ref(&p),
                std::slice::from_ref(&sent),
                &response,
                0
            ),
            expected
        );
    }
}

#[test]
fn retired_candidates_stop_matching_and_admission_recovers() {
    let mut index = CandidateIndex::new(2, 2);
    for generation in 0..4096 {
        let p = probe(
            Endpoint::Udp {
                port: 1000 + generation as u16,
            },
            generation as u64,
            false,
        );
        let sent = request(&p);
        index
            .insert(generation, generation % 2, &sent, &builtin::registry())
            .unwrap();
        let mut response = response_base(&sent);
        let udp = sent.get::<Udp>().unwrap();
        response.push(Udp {
            source_port: udp.destination_port,
            destination_port: udp.source_port,
            ..Default::default()
        });
        assert_eq!(index.lookup(generation % 2, &response), vec![generation]);
        index.remove(generation);
        assert!(index.lookup(generation % 2, &response).is_empty());
    }
}
