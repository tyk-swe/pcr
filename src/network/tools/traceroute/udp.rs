// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::anyhow;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::engine::command::TracerouteRequest;
use crate::util::error::operation_failed;
use anyhow::{Context, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter};

use super::common::{
    open_ipv4_channel, open_ipv6_channel, request_timeout, run_traceroute_loop, PacketReceiver,
    ProbeResult, TracerouteExecutor, UdpSocketV4, UdpSocketV6, DEFAULT_PORT,
};
use super::utils::{
    await_icmp_response_v4, await_icmp_response_v6, IcmpReceiverAdapter, Icmpv6ReceiverAdapter,
};

fn probe_destination_port(ttl: u8, probe: u8) -> Result<u16> {
    let ttl_offset = u16::from(ttl)
        .checked_mul(3)
        .and_then(|offset| offset.checked_add(u16::from(probe)))
        .ok_or_else(|| {
            anyhow!("traceroute port calculation overflowed: ttl={ttl} probe={probe}")
        })?;

    DEFAULT_PORT
        .checked_add(ttl_offset)
        .ok_or_else(|| anyhow!("traceroute port exceeded u16 range: ttl={ttl} probe={probe}"))
}

pub fn run_udp_traceroute_v4(destination: Ipv4Addr, opts: &TracerouteRequest) -> Result<()> {
    let bind_addr = (Ipv4Addr::UNSPECIFIED, 0);
    let socket = std::net::UdpSocket::bind(bind_addr)
        .with_context(|| operation_failed("bind UDP socket", format!("addr={bind_addr:?}")))?;

    let (sender, mut receiver) =
        open_ipv4_channel(IpNextHeaderProtocols::Icmp, "open ICMP channel")?;

    // Drop unused ICMP sender to release resources early
    drop(sender);

    let mut iter = icmp_packet_iter(&mut receiver);
    let mut adapter = IcmpReceiverAdapter(&mut iter);

    run_udp_traceroute_v4_loop(destination, opts, &socket, &mut adapter)?;

    // Explicitly drop channels to ensure cleanup
    drop(socket);

    Ok(())
}

struct UdpV4Executor<'a, S, R: ?Sized> {
    destination: Ipv4Addr,
    timeout: std::time::Duration,
    socket: &'a S,
    receiver: &'a mut R,
}

impl<'a, S, R: ?Sized> TracerouteExecutor for UdpV4Executor<'a, S, R>
where
    S: UdpSocketV4,
    R: super::common::PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        // Use predictable port offsets so responses can be mapped back to their TTL/probe pair.
        // Note: This heuristic can be fragile behind NATs that rewrite source ports or alter flow paths,
        // but it is the standard mechanism for UDP traceroute correlation without payload injection.
        let port = probe_destination_port(ttl, probe)?;
        self.socket.set_ttl(ttl as u32)?;
        let payload = [ttl, probe, 0xBE, 0xEF];
        self.socket
            .send_to(&payload, (self.destination, port))
            .with_context(|| {
                operation_failed(
                    "send UDP probe",
                    format!("destination={} port={port}", self.destination),
                )
            })?;

        await_icmp_response_v4(
            self.receiver,
            IpNextHeaderProtocols::Udp,
            port,
            Some((ttl, probe)),
            self.timeout,
        )
    }
}

pub fn run_udp_traceroute_v4_loop<S, R>(
    destination: Ipv4Addr,
    opts: &TracerouteRequest,
    socket: &S,
    receiver: &mut R,
) -> Result<()>
where
    S: UdpSocketV4,
    R: super::common::PacketReceiver + ?Sized,
{
    let mut executor = UdpV4Executor {
        destination,
        timeout: request_timeout(opts),
        socket,
        receiver,
    };
    run_traceroute_loop(opts, &mut executor)
}

struct UdpV6Executor<'a, S, R: ?Sized> {
    destination: Ipv6Addr,
    timeout: std::time::Duration,
    socket: &'a S,
    receiver: &'a mut R,
}

impl<'a, S, R: ?Sized> TracerouteExecutor for UdpV6Executor<'a, S, R>
where
    S: UdpSocketV6,
    R: PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        let port = probe_destination_port(ttl, probe)?;
        self.socket.set_unicast_hops_v6(u32::from(ttl))?;
        let payload = [ttl, probe, 0xBE, 0xEF];
        self.socket
            .send_to(&payload, (self.destination, port))
            .with_context(|| {
                operation_failed(
                    "send IPv6 UDP probe",
                    format!("destination={} port={port}", self.destination),
                )
            })?;

        await_icmp_response_v6(
            self.receiver,
            IpNextHeaderProtocols::Udp,
            port,
            Some((ttl, probe)),
            self.timeout,
        )
    }
}

pub fn run_udp_traceroute_v6_loop<S, R>(
    destination: Ipv6Addr,
    opts: &TracerouteRequest,
    socket: &S,
    receiver: &mut R,
) -> Result<()>
where
    S: UdpSocketV6,
    R: PacketReceiver + ?Sized,
{
    let mut executor = UdpV6Executor {
        destination,
        timeout: request_timeout(opts),
        socket,
        receiver,
    };
    run_traceroute_loop(opts, &mut executor)
}

pub fn run_udp_traceroute_v6(destination: Ipv6Addr, opts: &TracerouteRequest) -> Result<()> {
    let bind_addr = (Ipv6Addr::UNSPECIFIED, 0);
    let socket = std::net::UdpSocket::bind(bind_addr)
        .with_context(|| operation_failed("bind IPv6 UDP socket", format!("addr={bind_addr:?}")))?;

    let (sender, mut receiver) =
        open_ipv6_channel(IpNextHeaderProtocols::Icmpv6, "open ICMPv6 channel")?;

    // Drop unused ICMPv6 sender to release resources early
    drop(sender);

    let mut iter = icmpv6_packet_iter(&mut receiver);
    let mut adapter = Icmpv6ReceiverAdapter(&mut iter);

    run_udp_traceroute_v6_loop(destination, opts, &socket, &mut adapter)?;

    // Explicitly drop channels to ensure cleanup
    drop(socket);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::common::PacketReceiver;
    use super::*;
    use anyhow::Result;
    use pnet::packet::icmp::destination_unreachable::IcmpCodes as IcmpDestinationUnreachableCodes;
    use pnet::packet::icmp::{IcmpCode, IcmpType, IcmpTypes, MutableIcmpPacket};
    use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Type, Icmpv6Types, MutableIcmpv6Packet};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
    use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
    use pnet::packet::MutablePacket;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    type SentPacketsV4 = Vec<(Vec<u8>, (Ipv4Addr, u16))>;
    type SentPacketsV6 = Vec<(Vec<u8>, (Ipv6Addr, u16))>;

    #[derive(Default)]
    struct MockState {
        sent_v4: Mutex<SentPacketsV4>,
        sent_v6: Mutex<SentPacketsV6>,
        ttl_v4: Mutex<Option<u32>>,
        ttl_v6: Mutex<Option<u32>>,
    }

    struct MockSocket {
        state: Arc<MockState>,
    }

    impl MockSocket {
        fn new(state: Arc<MockState>) -> Self {
            Self { state }
        }
    }

    impl UdpSocketV4 for MockSocket {
        fn set_ttl(&self, ttl: u32) -> Result<()> {
            *self.state.ttl_v4.lock().expect("ttl lock") = Some(ttl);
            Ok(())
        }

        fn send_to(&self, buf: &[u8], addr: (Ipv4Addr, u16)) -> Result<usize> {
            self.state
                .sent_v4
                .lock()
                .expect("sent lock")
                .push((buf.to_vec(), addr));
            Ok(buf.len())
        }
    }

    impl UdpSocketV6 for MockSocket {
        fn set_unicast_hops_v6(&self, ttl: u32) -> Result<()> {
            *self.state.ttl_v6.lock().expect("ttl lock") = Some(ttl);
            Ok(())
        }

        fn send_to(&self, buf: &[u8], addr: (Ipv6Addr, u16)) -> Result<usize> {
            self.state
                .sent_v6
                .lock()
                .expect("sent lock")
                .push((buf.to_vec(), addr));
            Ok(buf.len())
        }
    }

    struct MockReceiver {
        responses: VecDeque<Option<(Vec<u8>, IpAddr)>>,
    }

    impl MockReceiver {
        fn new(responses: VecDeque<Option<(Vec<u8>, IpAddr)>>) -> Self {
            Self { responses }
        }
    }

    impl PacketReceiver for MockReceiver {
        fn next_packet(&mut self, _timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
            Ok(self.responses.pop_front().unwrap_or(None))
        }
    }

    struct SmartReceiver {
        state: Arc<MockState>,
        hops: VecDeque<IpAddr>,
        replied_count: usize,
    }

    impl SmartReceiver {
        fn new(state: Arc<MockState>, hops: Vec<IpAddr>) -> Self {
            Self {
                state,
                hops: VecDeque::from(hops),
                replied_count: 0,
            }
        }
    }

    impl PacketReceiver for SmartReceiver {
        fn next_packet(&mut self, _timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
            // Check V4
            {
                let sent = self.state.sent_v4.lock().unwrap();
                if sent.len() > self.replied_count {
                    let (_payload, (_, dest_port)) = &sent[self.replied_count];
                    // Reconstruct payload from ttl/probe?
                    // Actually, execute_probe sends [ttl, probe, 0xBE, 0xEF]
                    // We can just use the payload from the sent packet for the reply
                    let payload = [_payload[0], _payload[1], _payload[2], _payload[3]];

                    if let Some(hop) = self.hops.pop_front() {
                        self.replied_count += 1;
                        let is_final = self.hops.is_empty();
                        let response = if is_final {
                            build_icmpv4_udp_response(
                                *dest_port,
                                payload,
                                IcmpTypes::DestinationUnreachable,
                                IcmpDestinationUnreachableCodes::DestinationPortUnreachable,
                            )
                        } else {
                            build_icmpv4_udp_response(
                                *dest_port,
                                payload,
                                IcmpTypes::TimeExceeded,
                                IcmpCode::new(0),
                            )
                        };
                        return Ok(Some((response, hop)));
                    }
                }
            }
            // Check V6
            {
                let sent = self.state.sent_v6.lock().unwrap();
                if sent.len() > self.replied_count {
                    let (_payload, (_, dest_port)) = &sent[self.replied_count];
                    let payload = [_payload[0], _payload[1], _payload[2], _payload[3]];

                    if let Some(hop) = self.hops.pop_front() {
                        self.replied_count += 1;
                        let is_final = self.hops.is_empty();
                        let response = if is_final {
                            build_icmpv6_udp_response(
                                *dest_port,
                                payload,
                                Icmpv6Types::DestinationUnreachable,
                                Icmpv6Code(super::super::common::ICMPV6_PORT_UNREACHABLE_CODE),
                            )
                        } else {
                            build_icmpv6_udp_response(
                                *dest_port,
                                payload,
                                Icmpv6Types::TimeExceeded,
                                Icmpv6Code(0),
                            )
                        };
                        return Ok(Some((response, hop)));
                    }
                }
            }
            Ok(None)
        }
    }

    fn build_icmpv4_udp_response(
        dest_port: u16,
        payload: [u8; 4],
        icmp_type: IcmpType,
        icmp_code: IcmpCode,
    ) -> Vec<u8> {
        let udp_len = UdpPacket::minimum_packet_size() + payload.len();
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
            udp.set_destination(dest_port);
            udp.set_length(udp_len as u16);
            udp.set_payload(&payload);
        }

        let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
        {
            let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
            icmp.set_icmp_type(icmp_type);
            icmp.set_icmp_code(icmp_code);
            icmp.set_payload(&ipv4_bytes);
        }
        icmp_bytes
    }

    fn build_icmpv6_udp_response(
        dest_port: u16,
        payload: [u8; 4],
        icmp_type: Icmpv6Type,
        icmp_code: Icmpv6Code,
    ) -> Vec<u8> {
        let udp_len = UdpPacket::minimum_packet_size() + payload.len();
        let mut ipv6_bytes = vec![0u8; Ipv6Packet::minimum_packet_size() + udp_len];
        let ipv6_payload_len = udp_len as u16;
        {
            let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
            ipv6.set_version(6);
            ipv6.set_payload_length(ipv6_payload_len);
            ipv6.set_next_header(IpNextHeaderProtocols::Udp);
            let mut udp = MutableUdpPacket::new(ipv6.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(dest_port);
            udp.set_length(udp_len as u16);
            udp.set_payload(&payload);
        }

        let mut icmp_bytes =
            vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
        {
            let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
            icmp.set_icmpv6_type(icmp_type);
            icmp.set_icmpv6_code(icmp_code);
            icmp.set_payload(&ipv6_bytes);
        }
        icmp_bytes
    }

    #[test]
    fn run_udp_traceroute_v4_loop_sends_probe_and_stops_on_destination() {
        let destination = Ipv4Addr::new(203, 0, 113, 5);
        let opts = TracerouteRequest {
            destination: destination.to_string(),
            max_ttl: 1,
            probes: 1,
            timeout: 10,
            no_dns: Some(true),
            ..Default::default()
        };

        let state = Arc::new(MockState::default());
        let socket = MockSocket::new(state.clone());
        let dest_port = DEFAULT_PORT + 3;
        let payload = [1, 0, 0xBE, 0xEF];
        let icmp_packet = build_icmpv4_udp_response(
            dest_port,
            payload,
            IcmpTypes::DestinationUnreachable,
            IcmpDestinationUnreachableCodes::DestinationPortUnreachable,
        );
        let mut receiver = MockReceiver::new(VecDeque::from(vec![Some((
            icmp_packet,
            IpAddr::V4(destination),
        ))]));

        run_udp_traceroute_v4_loop(destination, &opts, &socket, &mut receiver)
            .expect("traceroute loop");

        let ttl = state.ttl_v4.lock().expect("ttl lock").unwrap_or(0);
        assert_eq!(ttl, 1);

        let sent = state.sent_v4.lock().expect("sent lock");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, payload);
        assert_eq!(sent[0].1, (destination, dest_port));
    }

    #[test]
    fn probe_destination_port_matches_expected_offsets() {
        assert_eq!(probe_destination_port(1, 0).unwrap(), DEFAULT_PORT + 3);
        assert_eq!(probe_destination_port(2, 0).unwrap(), DEFAULT_PORT + 6);
        assert_eq!(probe_destination_port(u8::MAX, u8::MAX).unwrap(), 34454);
    }

    #[test]
    fn test_udp_v4_traceroute_multi_hop() {
        let destination = Ipv4Addr::new(1, 2, 3, 4);
        let hop = Ipv4Addr::new(10, 0, 0, 1);
        let opts = TracerouteRequest {
            destination: destination.to_string(),
            max_ttl: 2,
            probes: 1,
            timeout: 100,
            no_dns: Some(true),
            ..Default::default()
        };

        let state = Arc::new(MockState::default());
        let socket = MockSocket::new(state.clone());
        // SmartReceiver will treat the last item as destination (final)
        let mut receiver = SmartReceiver::new(
            state.clone(),
            vec![IpAddr::V4(hop), IpAddr::V4(destination)],
        );

        run_udp_traceroute_v4_loop(destination, &opts, &socket, &mut receiver)
            .expect("traceroute loop");

        assert_eq!(state.sent_v4.lock().unwrap().len(), 2);
        assert_eq!(*state.ttl_v4.lock().unwrap(), Some(2));
    }

    #[test]
    fn test_udp_v4_traceroute_timeout() {
        let destination = Ipv4Addr::new(1, 2, 3, 4);
        let opts = TracerouteRequest {
            destination: destination.to_string(),
            max_ttl: 1,
            probes: 1,
            timeout: 10,
            no_dns: Some(true),
            ..Default::default()
        };

        let state = Arc::new(MockState::default());
        let socket = MockSocket::new(state.clone());
        let mut receiver = MockReceiver::new(VecDeque::from(vec![None]));

        run_udp_traceroute_v4_loop(destination, &opts, &socket, &mut receiver)
            .expect("traceroute loop");

        // Should have sent 1 probe
        assert_eq!(state.sent_v4.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_udp_v6_traceroute_success() {
        let destination = Ipv6Addr::LOCALHOST;
        let opts = TracerouteRequest {
            destination: destination.to_string(),
            max_ttl: 1,
            probes: 1,
            timeout: 100,
            no_dns: Some(true),
            ..Default::default()
        };

        let state = Arc::new(MockState::default());
        let socket = MockSocket::new(state.clone());
        let mut receiver = SmartReceiver::new(state.clone(), vec![IpAddr::V6(destination)]);

        run_udp_traceroute_v6_loop(destination, &opts, &socket, &mut receiver)
            .expect("traceroute loop");

        assert_eq!(state.sent_v6.lock().unwrap().len(), 1);
        assert_eq!(*state.ttl_v6.lock().unwrap(), Some(1));
    }

    #[test]
    fn test_udp_v6_traceroute_multi_hop() {
        let destination = Ipv6Addr::LOCALHOST;
        let hop = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let opts = TracerouteRequest {
            destination: destination.to_string(),
            max_ttl: 2,
            probes: 1,
            timeout: 100,
            no_dns: Some(true),
            ..Default::default()
        };

        let state = Arc::new(MockState::default());
        let socket = MockSocket::new(state.clone());
        let mut receiver = SmartReceiver::new(
            state.clone(),
            vec![IpAddr::V6(hop), IpAddr::V6(destination)],
        );

        run_udp_traceroute_v6_loop(destination, &opts, &socket, &mut receiver)
            .expect("traceroute loop");

        assert_eq!(state.sent_v6.lock().unwrap().len(), 2);
        assert_eq!(*state.ttl_v6.lock().unwrap(), Some(2));
    }
}
