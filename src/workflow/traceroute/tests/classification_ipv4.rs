use std::net::Ipv4Addr;

use super::super::*;
use super::support::{decoded_at, icmpv4_error, ipv4_udp_quote};
use crate::protocol::builtin::registry as default_registry;

#[test]
fn ipv4_classifier_accepts_intermediate_destination_and_unreachable_responses() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 9);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut udp_probe_packet = TracerouteProbe {
        sequence: 0,
        address: IpAddr::V4(remote),
        strategy: TracerouteStrategy::Udp,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT),
        hop_limit: 1,
        attempt: 1,
    }
    .packet();
    udp_probe_packet.get_mut::<Ipv4>().unwrap().source = local;
    let quote = ipv4_udp_quote(&udp_probe_packet);

    let intermediate = icmpv4_error(router, local, 11, 0, quote.clone(), 2, Vec::new());
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &intermediate,
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::Intermediate
    );
    let reached = icmpv4_error(remote, local, 3, 3, quote.clone(), 2, Vec::new());
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &reached,
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::DestinationReached
    );
    let unreachable = icmpv4_error(router, local, 3, 1, quote.clone(), 2, Vec::new());
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &unreachable,
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::Unreachable
    );
}

#[test]
fn ipv4_classifier_rejects_corrupt_unrelated_and_malformed_evidence() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 9);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut udp_probe_packet = TracerouteProbe {
        sequence: 0,
        address: IpAddr::V4(remote),
        strategy: TracerouteStrategy::Udp,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT),
        hop_limit: 1,
        attempt: 1,
    }
    .packet();
    udp_probe_packet.get_mut::<Ipv4>().unwrap().source = local;
    let quote = ipv4_udp_quote(&udp_probe_packet);

    let corrupt = icmpv4_error(
        router,
        local,
        11,
        0,
        quote,
        2,
        vec![Diagnostic::warning("icmpv4.checksum", "invalid checksum")],
    );
    assert!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &corrupt,
        )
        .is_none()
    );

    let mut unrelated_quote = ipv4_udp_quote(&udp_probe_packet);
    unrelated_quote[19] ^= 1;
    let unrelated = icmpv4_error(router, local, 11, 0, unrelated_quote, 2, Vec::new());
    assert!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &unrelated,
        )
        .is_none()
    );
    let malformed = icmpv4_error(router, local, 11, 0, vec![0_u8; 3], 2, Vec::new());
    assert!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &malformed,
        )
        .is_none()
    );
}

#[test]
fn tcp_strategy_builds_hop_limit_and_accepts_direct_terminal_reply() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 9);
    let mut tcp_request = TracerouteProbe {
        sequence: 17,
        address: IpAddr::V4(remote),
        strategy: TracerouteStrategy::Tcp,
        destination_port: Some(443),
        hop_limit: 7,
        attempt: 1,
    }
    .packet();
    assert_eq!(tcp_request.get::<Ipv4>().unwrap().ttl, 7);
    tcp_request.get_mut::<Ipv4>().unwrap().source = local;
    let mut tcp_reply = Packet::new();
    tcp_reply
        .push(Ipv4 {
            source: remote,
            destination: local,
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port: 443,
            destination_port: TRACEROUTE_SOURCE_PORT,
            flags: Tcp::SYN | Tcp::ACK,
            acknowledgment: 18,
            ..Tcp::default()
        });
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Tcp,
            &tcp_request,
            &decoded_at(tcp_reply.clone(), 2, Vec::new()),
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::DestinationReached
    );
    tcp_reply.get_mut::<Tcp>().unwrap().acknowledgment = 19;
    assert!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Tcp,
            &tcp_request,
            &decoded_at(tcp_reply, 2, Vec::new()),
        )
        .is_none()
    );
}
