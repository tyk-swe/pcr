// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

pub mod common;
pub mod icmp;
pub mod tcp;
pub mod udp;
pub mod utils;

#[cfg(test)]
mod tests_payload;

use std::net::IpAddr;

use anyhow::Result;
use log::info;

use crate::engine::command::{TracerouteProtocol, TracerouteRequest};
use crate::engine::policy::{
    classify_ip, TrafficMode, TrafficPlan, TrafficPrivilege, TrafficSelection,
    TrafficSelectionValue,
};
use crate::engine::EngineConfig;

use self::common::resolve_destination_with_reason;
use self::icmp::{run_icmp_traceroute_v4, run_icmp_traceroute_v6};
use self::tcp::{run_tcp_traceroute_v4, run_tcp_traceroute_v6};
use self::udp::{run_udp_traceroute_v4, run_udp_traceroute_v6};

#[derive(Debug, Clone)]
pub struct PreparedTraceroute {
    pub traffic_plan: TrafficPlan,
    pub destination: IpAddr,
    send_delay: Option<std::time::Duration>,
}

pub fn prepare(opts: &TracerouteRequest, config: &EngineConfig) -> Result<PreparedTraceroute> {
    let resolved_destination = resolve_destination_with_reason(&opts.destination)?;
    let destination = resolved_destination.address;
    let mut plan = TrafficPlan::new(TrafficMode::Traceroute, classify_ip(destination));
    plan.target_count = 1;
    plan.port_count = 1;
    plan.estimated_packets = Some(u64::from(opts.max_ttl) * u64::from(opts.probes));
    plan.batch_size = 1;
    plan.rate_per_sec = Some(config.traffic_policy.budget.max_rate_per_sec);
    plan.required_privileges = vec![TrafficPrivilege::RawSocket];
    plan.selection = Some(traceroute_selection(
        destination,
        resolved_destination.reason,
        opts.protocol,
    ));
    Ok(PreparedTraceroute {
        traffic_plan: plan,
        destination,
        send_delay: config.traffic_policy.rate_delay(),
    })
}

fn traceroute_selection(
    destination: IpAddr,
    destination_reason: &'static str,
    protocol: TracerouteProtocol,
) -> TrafficSelection {
    let (source_value, source_reason) = match (destination, protocol) {
        (IpAddr::V4(destination), TracerouteProtocol::Tcp) => (
            common::resolve_source_ipv4(destination)
                .ok()
                .map(|ip| ip.to_string()),
            "route_table",
        ),
        (IpAddr::V6(destination), TracerouteProtocol::Tcp | TracerouteProtocol::Icmp) => (
            common::resolve_source_ipv6(destination)
                .ok()
                .map(|ip| ip.to_string()),
            "route_table",
        ),
        _ => (None, "os_socket_selected"),
    };

    TrafficSelection {
        interface: None,
        source: Some(TrafficSelectionValue {
            value: source_value,
            reason: source_reason.to_string(),
        }),
        destination: Some(TrafficSelectionValue {
            value: Some(destination.to_string()),
            reason: destination_reason.to_string(),
        }),
    }
}

pub fn traffic_plan(opts: &TracerouteRequest, config: &EngineConfig) -> Result<TrafficPlan> {
    Ok(prepare(opts, config)?.traffic_plan)
}

pub async fn run(opts: &TracerouteRequest, config: &EngineConfig) -> Result<()> {
    let prepared = prepare(opts, config)?;
    run_prepared(opts, config, prepared).await
}

pub async fn run_prepared(
    opts: &TracerouteRequest,
    _config: &EngineConfig,
    prepared: PreparedTraceroute,
) -> Result<()> {
    tokio::task::spawn_blocking({
        let opts = opts.clone();
        move || traceroute_blocking(&opts, prepared.destination, prepared.send_delay)
    })
    .await??;
    Ok(())
}

fn traceroute_blocking(
    opts: &TracerouteRequest,
    destination: IpAddr,
    send_delay: Option<std::time::Duration>,
) -> Result<()> {
    info!(
        "Traceroute destination {} using {:?}",
        destination, opts.protocol
    );

    match destination {
        IpAddr::V4(dest_v4) => match opts.protocol {
            TracerouteProtocol::Udp => run_udp_traceroute_v4(dest_v4, opts, send_delay),
            TracerouteProtocol::Icmp => run_icmp_traceroute_v4(dest_v4, opts, send_delay),
            TracerouteProtocol::Tcp => run_tcp_traceroute_v4(dest_v4, opts, send_delay),
        },
        IpAddr::V6(dest_v6) => match opts.protocol {
            TracerouteProtocol::Udp => run_udp_traceroute_v6(dest_v6, opts, send_delay),
            TracerouteProtocol::Icmp => run_icmp_traceroute_v6(dest_v6, opts, send_delay),
            TracerouteProtocol::Tcp => run_tcp_traceroute_v6(dest_v6, opts, send_delay),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::common::{remaining_probe_time_at, ICMPV6_PORT_UNREACHABLE_CODE};
    use super::common::{resolve_destination, resolve_hostname, resolve_source_ipv4};
    use super::utils::{
        build_echo_request, classify_icmp_echo_v4, classify_icmp_event_v4, classify_icmp_event_v6,
        classify_icmpv6_echo_event, IcmpEventKind, ProbeEvent,
    };
    use pnet::packet::icmp::destination_unreachable::IcmpCodes as IcmpDestinationUnreachableCodes;
    use pnet::packet::icmp::echo_request::EchoRequestPacket;
    use pnet::packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
    use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
    use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
    use pnet::packet::MutablePacket;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    const ROUTER_SOLICITATION: pnet::packet::icmpv6::Icmpv6Type = Icmpv6Types::RouterSolicit;
    const TEST_TIMEOUT: Duration = Duration::from_secs(3);

    fn engine_config() -> crate::engine::EngineConfig {
        crate::engine::EngineConfig {
            output_format: None,
            prometheus_bind: None,
            rule_workers: None,
            rule_queue: None,
            send_workers: None,
            send_queue: None,
            traffic_policy: crate::engine::policy::TrafficPolicy::default(),
            dry_run: false,
        }
    }

    fn is_permission_error(err: &anyhow::Error) -> bool {
        err.chain().any(|cause| {
            if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
                return io_err.kind() == std::io::ErrorKind::PermissionDenied;
            }
            let message = cause.to_string();
            message.contains("Operation not permitted") || message.contains("permission denied")
        })
    }

    #[test]
    fn remaining_probe_time_returns_zero_at_exact_timeout() {
        let start = Instant::now();
        let deadline = start.checked_add(TEST_TIMEOUT).expect("instant adjustment");
        assert_eq!(
            remaining_probe_time_at(start, deadline, TEST_TIMEOUT),
            Some(Duration::ZERO),
        );
    }

    #[test]
    fn build_echo_request_sets_fields_and_checksum() {
        let mut buffer = [0u8; 32];
        build_echo_request(&mut buffer, 0x1234, 0x5678).expect("icmp build");
        let packet = IcmpPacket::new(&buffer).expect("icmp packet");
        assert_eq!(packet.get_icmp_type(), IcmpTypes::EchoRequest);
        let expected = pnet::packet::icmp::checksum(&packet);
        assert_eq!(packet.get_checksum(), expected);

        let packet = EchoRequestPacket::new(&buffer).expect("echo request packet view");
        assert_eq!(packet.get_identifier(), 0x1234);
        assert_eq!(packet.get_sequence_number(), 0x5678);
    }

    #[test]
    fn resolve_hostname_respects_no_dns_flag() {
        let addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let result = resolve_hostname(addr, true);
        assert_eq!(result, "1.2.3.4");
    }

    #[test]
    fn resolve_destination_accepts_ipv4_literal() {
        let addr = resolve_destination("127.0.0.1").expect("resolved destination");
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn prepare_uses_resolved_destination_for_execution() {
        let opts = crate::engine::command::TracerouteRequest {
            destination: "localhost".to_string(),
            max_ttl: 1,
            probes: 1,
            protocol: crate::engine::command::TracerouteProtocol::Udp,
            no_dns: None,
            timeout: 1,
        };

        let prepared = super::prepare(&opts, &engine_config()).expect("prepare traceroute");

        assert!(prepared.destination.is_loopback());
        assert_eq!(
            prepared.traffic_plan.target_scope,
            crate::engine::policy::TargetScope::Local
        );
        let selection = prepared
            .traffic_plan
            .selection
            .as_ref()
            .expect("traceroute selection metadata");
        assert_eq!(
            selection
                .destination
                .as_ref()
                .map(|value| value.reason.as_str()),
            Some("hostname_resolution")
        );
        assert_eq!(
            selection.source.as_ref().map(|value| value.reason.as_str()),
            Some("os_socket_selected")
        );
    }

    #[test]
    fn prepare_reports_tcp_source_selection_when_discovery_succeeds() {
        let opts = crate::engine::command::TracerouteRequest {
            destination: "127.0.0.1".to_string(),
            max_ttl: 1,
            probes: 1,
            protocol: crate::engine::command::TracerouteProtocol::Tcp,
            no_dns: None,
            timeout: 1,
        };

        let prepared = super::prepare(&opts, &engine_config()).expect("prepare traceroute");
        let source = prepared
            .traffic_plan
            .selection
            .as_ref()
            .and_then(|selection| selection.source.as_ref())
            .expect("source selection");

        assert_eq!(source.reason, "route_table");
        assert_eq!(source.value.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn resolve_source_ipv4_returns_local_address() {
        match resolve_source_ipv4(Ipv4Addr::LOCALHOST) {
            Ok(addr) => assert_eq!(addr, Ipv4Addr::LOCALHOST),
            Err(err) if is_permission_error(&err) => {}
            Err(err) => panic!("unexpected source discovery error: {err}"),
        }
    }

    #[test]
    fn classify_icmp_event_v4_treats_non_port_unreachable_as_hop() {
        let udp_len = UdpPacket::minimum_packet_size();
        let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + udp_len];
        let ipv4_len = ipv4_bytes.len() as u16;
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(ipv4_len);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(4321);
        }

        let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
        {
            let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
            icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
            icmp.set_icmp_code(IcmpDestinationUnreachableCodes::DestinationHostUnreachable);
            icmp.set_payload(&ipv4_bytes);
        }

        let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
        let kind = classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, 4321, None)
            .expect("event should match expected destination");
        assert!(matches!(kind, IcmpEventKind::Hop));
    }

    #[test]
    fn classify_icmp_event_v4_treats_port_unreachable_as_destination() {
        let udp_len = UdpPacket::minimum_packet_size();
        let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + udp_len];
        let ipv4_len = ipv4_bytes.len() as u16;
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(ipv4_len);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(4321);
        }

        let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
        {
            let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
            icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
            icmp.set_icmp_code(IcmpDestinationUnreachableCodes::DestinationPortUnreachable);
            icmp.set_payload(&ipv4_bytes);
        }

        let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
        let kind = classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, 4321, None)
            .expect("event should match expected destination");
        assert!(matches!(kind, IcmpEventKind::Destination));
    }

    #[test]
    fn classify_icmp_event_v6_treats_non_port_unreachable_as_hop() {
        let udp_len = UdpPacket::minimum_packet_size();
        let mut ipv6_bytes = vec![0u8; Ipv6Packet::minimum_packet_size() + udp_len];
        {
            let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
            ipv6.set_version(6);
            ipv6.set_payload_length(udp_len as u16);
            ipv6.set_next_header(IpNextHeaderProtocols::Udp);
            let mut udp = MutableUdpPacket::new(ipv6.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(4321);
        }

        let mut icmp_bytes =
            vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
        {
            let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
            icmp.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
            icmp.set_icmpv6_code(Icmpv6Code(1));
            icmp.set_payload(&ipv6_bytes);
        }

        let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
        let kind = classify_icmp_event_v6(&packet, IpNextHeaderProtocols::Udp, 4321, None)
            .expect("event should match expected destination");
        assert!(matches!(kind, IcmpEventKind::Hop));
    }

    #[test]
    fn classify_icmp_event_v6_treats_port_unreachable_as_destination() {
        let udp_len = UdpPacket::minimum_packet_size();
        let mut ipv6_bytes = vec![0u8; Ipv6Packet::minimum_packet_size() + udp_len];
        {
            let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
            ipv6.set_version(6);
            ipv6.set_payload_length(udp_len as u16);
            ipv6.set_next_header(IpNextHeaderProtocols::Udp);
            let mut udp = MutableUdpPacket::new(ipv6.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(4321);
        }

        let mut icmp_bytes =
            vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
        {
            let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
            icmp.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
            icmp.set_icmpv6_code(Icmpv6Code(ICMPV6_PORT_UNREACHABLE_CODE));
            icmp.set_payload(&ipv6_bytes);
        }

        let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
        let kind = classify_icmp_event_v6(&packet, IpNextHeaderProtocols::Udp, 4321, None)
            .expect("event should match expected destination");
        assert!(matches!(kind, IcmpEventKind::Destination));
    }

    #[test]
    fn resolve_destination_accepts_ipv6_literal() {
        let addr = resolve_destination("::1").expect("resolved IPv6 destination");
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn resolve_destination_accepts_hostname() {
        // Using localhost as a reliable hostname across platforms
        let result = resolve_destination("localhost");
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert!(addr.is_loopback());
    }

    #[test]
    fn resolve_destination_fails_for_invalid_hostname() {
        let result = resolve_destination("this.hostname.definitely.does.not.exist.invalid");
        assert!(result.is_err());
    }

    #[test]
    fn remaining_probe_time_at_returns_full_timeout_at_start() {
        let start = Instant::now();
        let now = start;
        let remaining = remaining_probe_time_at(start, now, TEST_TIMEOUT).expect("remaining time");
        assert_eq!(remaining, TEST_TIMEOUT);
    }

    #[test]
    fn remaining_probe_time_at_decreases_with_elapsed_time() {
        let start = Instant::now();
        let now = start
            .checked_add(Duration::from_secs(1))
            .expect("instant adjustment");
        let remaining = remaining_probe_time_at(start, now, TEST_TIMEOUT).expect("remaining time");
        assert_eq!(remaining, TEST_TIMEOUT - Duration::from_secs(1));
    }

    #[test]
    fn remaining_probe_time_at_returns_none_when_now_before_start() {
        let start = Instant::now();
        let now = start
            .checked_sub(Duration::from_millis(1))
            .expect("instant adjustment");
        assert!(remaining_probe_time_at(start, now, TEST_TIMEOUT).is_none());
    }

    #[test]
    fn classify_icmp_echo_v4_recognizes_echo_reply() {
        let mut buffer = [0u8; 32];
        build_echo_request(&mut buffer, 0x1111, 0x2222).expect("echo request");
        // Modify to be an echo reply
        {
            let mut packet = MutableIcmpPacket::new(&mut buffer).expect("mutable icmp");
            packet.set_icmp_type(IcmpTypes::EchoReply);
            let checksum = pnet::packet::icmp::checksum(&packet.to_immutable());
            packet.set_checksum(checksum);
        }

        let packet = IcmpPacket::new(&buffer).expect("icmp packet");
        let result = classify_icmp_echo_v4(
            &packet,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            0x1111,
            0x2222,
        )
        .expect("classification result");

        assert!(matches!(result, Some(ProbeEvent::Destination(_))));
    }

    #[test]
    fn classify_icmp_echo_v4_ignores_mismatched_identifier() {
        let mut buffer = [0u8; 32];
        build_echo_request(&mut buffer, 0x1111, 0x2222).expect("echo request");
        {
            let mut packet = MutableIcmpPacket::new(&mut buffer).expect("mutable icmp");
            packet.set_icmp_type(IcmpTypes::EchoReply);
            let checksum = pnet::packet::icmp::checksum(&packet.to_immutable());
            packet.set_checksum(checksum);
        }

        let packet = IcmpPacket::new(&buffer).expect("icmp packet");
        // Try with wrong identifier
        let result = classify_icmp_echo_v4(
            &packet,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            0x9999, // Wrong identifier
            0x2222,
        )
        .expect("should not error");

        assert!(result.is_none());
    }

    #[test]
    fn classify_icmp_echo_v4_ignores_mismatched_sequence() {
        let mut buffer = [0u8; 32];
        build_echo_request(&mut buffer, 0x1111, 0x2222).expect("echo request");
        {
            let mut packet = MutableIcmpPacket::new(&mut buffer).expect("mutable icmp");
            packet.set_icmp_type(IcmpTypes::EchoReply);
            let checksum = pnet::packet::icmp::checksum(&packet.to_immutable());
            packet.set_checksum(checksum);
        }

        let packet = IcmpPacket::new(&buffer).expect("icmp packet");
        // Try with wrong sequence
        let result = classify_icmp_echo_v4(
            &packet,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            0x1111,
            0x9999, // Wrong sequence
        )
        .expect("should not error");

        assert!(result.is_none());
    }

    #[test]
    fn classify_icmp_echo_v4_ignores_unrelated_icmp_types() {
        let mut buffer = [0u8; 32];
        {
            let mut packet = MutableIcmpPacket::new(&mut buffer).expect("mutable icmp");
            packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
        }

        let packet = IcmpPacket::new(&buffer).expect("icmp packet");
        let result = classify_icmp_echo_v4(
            &packet,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            0x1111,
            0x2222,
        )
        .expect("should not error");

        assert!(result.is_none());
    }

    #[test]
    fn classify_icmpv6_echo_event_recognizes_echo_reply() {
        let mut buffer = [0u8; 12];
        {
            let mut packet = MutableIcmpv6Packet::new(&mut buffer).expect("icmpv6 packet");
            packet.set_icmpv6_type(Icmpv6Types::EchoReply);
            packet.set_icmpv6_code(Icmpv6Code(0));
            // Set echo payload (identifier and sequence)
            packet.set_payload(&[0x11, 0x22, 0x33, 0x44]);
        }

        let packet = Icmpv6Packet::new(&buffer).expect("icmpv6 packet");
        let result = classify_icmpv6_echo_event(
            &packet,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            0x1122,
            0x3344,
        );

        assert!(matches!(result, Some(ProbeEvent::Destination(_))));
    }

    #[test]
    fn classify_icmpv6_echo_event_ignores_mismatched_echo_reply() {
        let mut buffer = [0u8; 12];
        {
            let mut packet = MutableIcmpv6Packet::new(&mut buffer).expect("icmpv6 packet");
            packet.set_icmpv6_type(Icmpv6Types::EchoReply);
            packet.set_icmpv6_code(Icmpv6Code(0));
            packet.set_payload(&[0x11, 0x22, 0x33, 0x44]);
        }

        let packet = Icmpv6Packet::new(&buffer).expect("icmpv6 packet");
        // Try with wrong identifier
        let result = classify_icmpv6_echo_event(
            &packet,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            0x9999, // Wrong identifier
            0x3344,
        );

        assert!(result.is_none());
    }

    #[test]
    fn classify_icmpv6_echo_event_ignores_unrelated_types() {
        let mut buffer = [0u8; 12];
        {
            let mut packet = MutableIcmpv6Packet::new(&mut buffer).expect("icmpv6 packet");
            packet.set_icmpv6_type(ROUTER_SOLICITATION);
            packet.set_icmpv6_code(Icmpv6Code(0));
        }

        let packet = Icmpv6Packet::new(&buffer).expect("icmpv6 packet");
        let result = classify_icmpv6_echo_event(
            &packet,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            0x1122,
            0x3344,
        );

        assert!(result.is_none());
    }

    #[test]
    fn classify_icmp_event_v4_returns_none_for_wrong_port() {
        let udp_len = UdpPacket::minimum_packet_size();
        let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + udp_len];
        let ipv4_len = ipv4_bytes.len() as u16;
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(ipv4_len);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(4321);
        }

        let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
        {
            let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
            icmp.set_icmp_type(IcmpTypes::TimeExceeded);
            icmp.set_payload(&ipv4_bytes);
        }

        let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
        // Try with wrong expected port
        let result = classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, 9999, None);
        assert!(result.is_none());
    }

    #[test]
    fn classify_icmp_event_v6_returns_none_for_wrong_port() {
        let udp_len = UdpPacket::minimum_packet_size();
        let mut ipv6_bytes = vec![0u8; Ipv6Packet::minimum_packet_size() + udp_len];
        {
            let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
            ipv6.set_version(6);
            ipv6.set_payload_length(udp_len as u16);
            ipv6.set_next_header(IpNextHeaderProtocols::Udp);
            let mut udp = MutableUdpPacket::new(ipv6.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(4321);
        }

        let mut icmp_bytes =
            vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
        {
            let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
            icmp.set_icmpv6_type(Icmpv6Types::TimeExceeded);
            icmp.set_payload(&ipv6_bytes);
        }

        let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
        // Try with wrong expected port
        let result = classify_icmp_event_v6(&packet, IpNextHeaderProtocols::Udp, 9999, None);
        assert!(result.is_none());
    }
}

#[cfg(test)]
mod additional_tests {
    use super::common::{PacketReceiver, ProbeResult, UdpSocketV4, DEFAULT_PORT};
    use super::udp::run_udp_traceroute_v4_loop;
    use super::utils::ProbeEvent;
    use crate::engine::command::{TracerouteProtocol, TracerouteRequest};
    use anyhow::Result;
    use pnet::packet::icmp::destination_unreachable::IcmpCodes as IcmpDestinationUnreachableCodes;
    use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::MutablePacket;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    type SentPacket = (Vec<u8>, (Ipv4Addr, u16));

    struct MockUdpSocket {
        sent: RefCell<Vec<SentPacket>>,
        ttls: RefCell<Vec<u32>>,
    }

    impl MockUdpSocket {
        fn new() -> Self {
            Self {
                sent: RefCell::new(Vec::new()),
                ttls: RefCell::new(Vec::new()),
            }
        }
    }

    impl UdpSocketV4 for MockUdpSocket {
        fn set_ttl(&self, ttl: u32) -> Result<()> {
            self.ttls.borrow_mut().push(ttl);
            Ok(())
        }

        fn send_to(&self, buf: &[u8], addr: (Ipv4Addr, u16)) -> Result<usize> {
            self.sent.borrow_mut().push((buf.to_vec(), addr));
            Ok(buf.len())
        }
    }

    struct MockPacketReceiver {
        responses: VecDeque<Option<(Vec<u8>, IpAddr)>>,
    }

    impl PacketReceiver for MockPacketReceiver {
        fn next_packet(&mut self, _timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
            Ok(self.responses.pop_front().flatten())
        }
    }

    fn build_icmp_time_exceeded_v4(
        protocol: pnet::packet::ip::IpNextHeaderProtocol,
        dest_port: u16,
    ) -> Vec<u8> {
        let mut ipv4_bytes = vec![0u8; 20 + 8];
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).unwrap();
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(28);
            ipv4.set_next_level_protocol(protocol);
            let payload = ipv4.payload_mut();
            // UDP destination port is at offset 2
            payload[2] = (dest_port >> 8) as u8;
            payload[3] = (dest_port & 0xFF) as u8;
        }

        let mut icmp_bytes = vec![0u8; 8 + ipv4_bytes.len()];
        {
            let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).unwrap();
            icmp.set_icmp_type(IcmpTypes::TimeExceeded);
            icmp.set_payload(&ipv4_bytes);
            let checksum = pnet::packet::icmp::checksum(&icmp.to_immutable());
            icmp.set_checksum(checksum);
        }
        icmp_bytes
    }

    fn build_icmp_dest_unreachable_v4(
        protocol: pnet::packet::ip::IpNextHeaderProtocol,
        dest_port: u16,
    ) -> Vec<u8> {
        let mut ipv4_bytes = vec![0u8; 20 + 8];
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).unwrap();
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(28);
            ipv4.set_next_level_protocol(protocol);
            let payload = ipv4.payload_mut();
            payload[2] = (dest_port >> 8) as u8;
            payload[3] = (dest_port & 0xFF) as u8;
        }

        let mut icmp_bytes = vec![0u8; 8 + ipv4_bytes.len()];
        {
            let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).unwrap();
            icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
            icmp.set_icmp_code(IcmpDestinationUnreachableCodes::DestinationPortUnreachable);
            icmp.set_payload(&ipv4_bytes);
            let checksum = pnet::packet::icmp::checksum(&icmp.to_immutable());
            icmp.set_checksum(checksum);
        }
        icmp_bytes
    }

    #[test]
    fn run_udp_traceroute_v4_loop_sends_probes_and_handles_responses() {
        let opts = TracerouteRequest {
            destination: "127.0.0.1".to_string(),
            protocol: TracerouteProtocol::Udp,
            max_ttl: 2,
            probes: 1,
            no_dns: Some(true),
            timeout: 3000,
        };
        let destination = Ipv4Addr::LOCALHOST;
        let socket = MockUdpSocket::new();

        // Response for TTL 1 (Hop)
        // Note: run_udp_traceroute_v4_loop calculates port: DEFAULT_PORT + (ttl * 3 + probe)
        // TTL 1 Probe 0: 33434 + 3 = 33437
        let hop_packet = build_icmp_time_exceeded_v4(IpNextHeaderProtocols::Udp, DEFAULT_PORT + 3);

        // Response for TTL 2 (Destination)
        // TTL 2 Probe 0: 33434 + 6 = 33440
        let dest_packet =
            build_icmp_dest_unreachable_v4(IpNextHeaderProtocols::Udp, DEFAULT_PORT + 6);

        let mut receiver = MockPacketReceiver {
            responses: VecDeque::from([
                Some((hop_packet, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))),
                Some((dest_packet, IpAddr::V4(destination))),
            ]),
        };

        run_udp_traceroute_v4_loop(destination, &opts, &socket, &mut receiver)
            .expect("traceroute loop");

        let ttls = socket.ttls.borrow();
        assert_eq!(*ttls, vec![1, 2]);

        let sent = socket.sent.borrow();
        assert_eq!(sent.len(), 2);
    }

    #[test]
    fn run_probe_loop_retries_after_empty_poll() {
        let mut responses = VecDeque::from([
            Ok(None),
            Ok(Some(ProbeEvent::Destination(IpAddr::V4(
                Ipv4Addr::LOCALHOST,
            )))),
        ]);
        let mut polls = 0usize;
        let timeout = Duration::from_secs(1);
        let result = crate::network::traceroute::utils::run_probe_loop(timeout, |_| {
            polls += 1;
            responses.pop_front().unwrap_or(Ok(None))
        })
        .expect("probe result");

        let (addr, _) = match result {
            ProbeResult::Destination(addr, elapsed) => (addr, elapsed),
            _ => panic!("expected destination result"),
        };
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(polls >= 2, "probe should continue after empty poll");
    }

    #[test]
    fn run_probe_loop_times_out_after_deadline() {
        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(100);
        let result = crate::network::traceroute::utils::run_probe_loop(timeout, |_| Ok(None))
            .expect("probe result");

        if !matches!(result, ProbeResult::Timeout) {
            panic!("expected timeout result");
        }
        assert!(
            start.elapsed() >= timeout,
            "probe should wait for the configured timeout"
        );
    }
}
