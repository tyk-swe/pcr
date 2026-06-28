// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter};
use rand::random;

use crate::engine::command::TracerouteRequest;
use crate::engine::spec::Icmpv6Spec;
use crate::network::sender::build_icmpv6_segment;
use crate::util::error::operation_failed;

use super::common::{
    open_ipv4_channel, open_ipv6_channel, request_timeout, resolve_source_ipv6,
    run_traceroute_loop_with_delay, PacketReceiver, ProbeResult, TracerouteExecutor,
    TransportSender,
};
use super::utils::{
    await_icmp_echo_v4, await_icmpv6_echo, build_echo_request, IcmpReceiverAdapter,
    Icmpv6ReceiverAdapter,
};

#[cfg(test)]
use super::utils::parse_icmpv6_echo;

struct IcmpV4Executor<'a, S, R: ?Sized> {
    destination: Ipv4Addr,
    timeout: std::time::Duration,
    sender: &'a mut S,
    receiver: &'a mut R,
    identifier: u16,
}

impl<'a, S, R: ?Sized> TracerouteExecutor for IcmpV4Executor<'a, S, R>
where
    S: TransportSender,
    R: PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        let sequence = (ttl as u16).wrapping_mul(10).wrapping_add(probe as u16);
        let mut buffer = [0u8; 32];
        build_echo_request(&mut buffer, self.identifier, sequence)?;
        self.sender.set_ttl(ttl)?;
        self.sender
            .send_icmp_v4(
                IcmpPacket::new(&buffer).context(operation_failed(
                    "create ICMP packet",
                    "payload=echo request",
                ))?,
                IpAddr::V4(self.destination),
            )
            .context(operation_failed(
                "send ICMP probe",
                format!(
                    "destination={} identifier={} sequence={}",
                    self.destination, self.identifier, sequence
                ),
            ))?;

        await_icmp_echo_v4(self.receiver, self.identifier, sequence, self.timeout)
    }
}

pub fn run_icmp_traceroute_v4(
    destination: Ipv4Addr,
    opts: &TracerouteRequest,
    send_delay: Option<std::time::Duration>,
) -> Result<()> {
    let (mut sender, mut receiver) =
        open_ipv4_channel(IpNextHeaderProtocols::Icmp, "open ICMP channel")?;
    let mut iter = icmp_packet_iter(&mut receiver);
    let mut adapter = IcmpReceiverAdapter(&mut iter);

    run_icmp_traceroute_v4_loop_with_delay(
        destination,
        opts,
        send_delay,
        &mut sender,
        &mut adapter,
    )?;

    // Explicitly drop channels to ensure cleanup
    drop(sender);

    Ok(())
}

pub fn run_icmp_traceroute_v4_loop<S, R>(
    destination: Ipv4Addr,
    opts: &TracerouteRequest,
    sender: &mut S,
    receiver: &mut R,
) -> Result<()>
where
    S: TransportSender,
    R: PacketReceiver + ?Sized,
{
    run_icmp_traceroute_v4_loop_with_delay(destination, opts, None, sender, receiver)
}

fn run_icmp_traceroute_v4_loop_with_delay<S, R>(
    destination: Ipv4Addr,
    opts: &TracerouteRequest,
    send_delay: Option<std::time::Duration>,
    sender: &mut S,
    receiver: &mut R,
) -> Result<()>
where
    S: TransportSender,
    R: PacketReceiver + ?Sized,
{
    let identifier = random::<u16>();

    let mut executor = IcmpV4Executor {
        destination,
        timeout: request_timeout(opts),
        sender,
        receiver,
        identifier,
    };

    run_traceroute_loop_with_delay(opts, &mut executor, send_delay)
}

struct IcmpV6Executor<'a, S, R: ?Sized> {
    destination: Ipv6Addr,
    source_ip: Ipv6Addr,
    timeout: std::time::Duration,
    sender: &'a mut S,
    receiver: &'a mut R,
    identifier: u16,
}

impl<'a, S, R: ?Sized> TracerouteExecutor for IcmpV6Executor<'a, S, R>
where
    S: TransportSender,
    R: PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        let sequence = (ttl as u16).wrapping_mul(10).wrapping_add(probe as u16);
        let spec = Icmpv6Spec {
            kind: Some(Icmpv6Types::EchoRequest.0),
            code: Some(0),
            identifier: Some(self.identifier),
            sequence: Some(sequence),
            parameter: None,
        };
        let segment = build_icmpv6_segment(
            &spec,
            &[],
            IpAddr::V6(self.source_ip),
            IpAddr::V6(self.destination),
        )?;
        let packet = Icmpv6Packet::new(&segment).context(operation_failed(
            "construct ICMPv6 packet",
            format!(
                "destination={} identifier={} sequence={}",
                self.destination, self.identifier, sequence
            ),
        ))?;
        self.sender.set_ttl(ttl)?;
        self.sender
            .send_icmp_v6(packet, IpAddr::V6(self.destination))
            .context(operation_failed(
                "send ICMPv6 probe",
                format!(
                    "destination={} identifier={} sequence={}",
                    self.destination, self.identifier, sequence
                ),
            ))?;

        await_icmpv6_echo(self.receiver, self.identifier, sequence, self.timeout)
    }
}

pub fn run_icmp_traceroute_v6(
    destination: Ipv6Addr,
    opts: &TracerouteRequest,
    send_delay: Option<std::time::Duration>,
) -> Result<()> {
    let source_ip = resolve_source_ipv6(destination)?;
    let (mut sender, mut receiver) = open_ipv6_channel(
        IpNextHeaderProtocols::Icmpv6,
        "open ICMPv6 transport channel",
    )?;
    let mut iter = icmpv6_packet_iter(&mut receiver);
    let mut adapter = Icmpv6ReceiverAdapter(&mut iter);

    run_icmp_traceroute_v6_loop_with_delay(
        destination,
        source_ip,
        opts,
        send_delay,
        &mut sender,
        &mut adapter,
    )?;

    // Explicitly drop channels to ensure cleanup
    drop(sender);

    Ok(())
}

pub fn run_icmp_traceroute_v6_loop<S, R>(
    destination: Ipv6Addr,
    source_ip: Ipv6Addr,
    opts: &TracerouteRequest,
    sender: &mut S,
    receiver: &mut R,
) -> Result<()>
where
    S: TransportSender,
    R: PacketReceiver + ?Sized,
{
    run_icmp_traceroute_v6_loop_with_delay(destination, source_ip, opts, None, sender, receiver)
}

fn run_icmp_traceroute_v6_loop_with_delay<S, R>(
    destination: Ipv6Addr,
    source_ip: Ipv6Addr,
    opts: &TracerouteRequest,
    send_delay: Option<std::time::Duration>,
    sender: &mut S,
    receiver: &mut R,
) -> Result<()>
where
    S: TransportSender,
    R: PacketReceiver + ?Sized,
{
    let identifier = random::<u16>();

    let mut executor = IcmpV6Executor {
        destination,
        source_ip,
        timeout: request_timeout(opts),
        sender,
        receiver,
        identifier,
    };

    run_traceroute_loop_with_delay(opts, &mut executor, send_delay)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
    use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet};
    use pnet::packet::{MutablePacket, Packet};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MockState {
        sent_v4: Mutex<Vec<(Vec<u8>, IpAddr)>>,
        sent_v6: Mutex<Vec<(Vec<u8>, IpAddr)>>,
        ttl: Mutex<Option<u8>>,
    }

    struct MockTransportSender {
        state: Arc<MockState>,
    }

    impl MockTransportSender {
        fn new(state: Arc<MockState>) -> Self {
            Self { state }
        }
    }

    impl TransportSender for MockTransportSender {
        fn set_ttl(&mut self, ttl: u8) -> Result<()> {
            *self.state.ttl.lock().unwrap() = Some(ttl);
            Ok(())
        }

        fn send_icmp_v4(&mut self, packet: IcmpPacket, destination: IpAddr) -> Result<usize> {
            self.state
                .sent_v4
                .lock()
                .unwrap()
                .push((packet.packet().to_vec(), destination));
            Ok(packet.packet().len())
        }

        fn send_icmp_v6(&mut self, packet: Icmpv6Packet, destination: IpAddr) -> Result<usize> {
            self.state
                .sent_v6
                .lock()
                .unwrap()
                .push((packet.packet().to_vec(), destination));
            Ok(packet.packet().len())
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
        fn next_packet(
            &mut self,
            _timeout: std::time::Duration,
        ) -> Result<Option<(Vec<u8>, IpAddr)>> {
            Ok(self.responses.pop_front().flatten())
        }
    }

    fn build_icmpv4_echo_reply(identifier: u16, sequence: u16) -> Vec<u8> {
        let mut buffer = vec![0u8; 8];
        {
            let mut packet =
                pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut buffer)
                    .unwrap();
            packet.set_icmp_type(IcmpTypes::EchoReply);
            packet.set_identifier(identifier);
            packet.set_sequence_number(sequence);
            let checksum = pnet::packet::icmp::checksum(&IcmpPacket::new(packet.packet()).unwrap());
            packet.set_checksum(checksum);
        }
        buffer
    }

    fn build_icmpv6_echo_reply(identifier: u16, sequence: u16) -> Vec<u8> {
        let mut buffer = vec![0u8; 8];
        {
            let mut packet = MutableIcmpv6Packet::new(&mut buffer).unwrap();
            packet.set_icmpv6_type(Icmpv6Types::EchoReply);
            packet.set_icmpv6_code(Icmpv6Code(0));
            let payload = [
                (identifier >> 8) as u8,
                (identifier & 0xff) as u8,
                (sequence >> 8) as u8,
                (sequence & 0xff) as u8,
            ];
            packet.set_payload(&payload);
            // Checksum is usually calculated by the OS for ICMPv6 transport channels,
            // but our classifier doesn't check it, so 0 is fine for the mock.
        }
        buffer
    }

    fn build_icmpv6_time_exceeded(identifier: u16, sequence: u16) -> Vec<u8> {
        let mut ipv6_bytes = vec![0u8; 40 + 8];
        ipv6_bytes[0] = 0x60; // Version 6
        ipv6_bytes[6] = 58; // Next header ICMPv6
        ipv6_bytes[40] = 128; // Type Echo Request
        ipv6_bytes[44] = (identifier >> 8) as u8;
        ipv6_bytes[45] = (identifier & 0xff) as u8;
        ipv6_bytes[46] = (sequence >> 8) as u8;
        ipv6_bytes[47] = (sequence & 0xff) as u8;

        let mut buffer = vec![0u8; 8 + ipv6_bytes.len()];
        {
            let mut packet = MutableIcmpv6Packet::new(&mut buffer).unwrap();
            packet.set_icmpv6_type(Icmpv6Types::TimeExceeded);
            packet.set_icmpv6_code(Icmpv6Code(0));
            packet.payload_mut()[4..].copy_from_slice(&ipv6_bytes);
        }
        buffer
    }

    fn build_icmpv4_time_exceeded(identifier: u16, sequence: u16) -> Vec<u8> {
        let mut ipv4_bytes = vec![0u8; 20 + 8];
        ipv4_bytes[0] = 0x45; // Version 4, IHL 5
        ipv4_bytes[9] = 1; // Protocol ICMP
                           // ICMP echo request starts at offset 20
        ipv4_bytes[20] = 8; // Type Echo Request
        ipv4_bytes[24] = (identifier >> 8) as u8;
        ipv4_bytes[25] = (identifier & 0xff) as u8;
        ipv4_bytes[26] = (sequence >> 8) as u8;
        ipv4_bytes[27] = (sequence & 0xff) as u8;

        let mut buffer = vec![0u8; 8 + ipv4_bytes.len()];
        {
            let mut packet = MutableIcmpPacket::new(&mut buffer).unwrap();
            packet.set_icmp_type(IcmpTypes::TimeExceeded);
            packet.set_icmp_code(pnet::packet::icmp::IcmpCode::new(0));
            // ICMP Time Exceeded has 4 bytes of "unused" after the 4-byte header,
            // then the original IP header follows.
            packet.payload_mut()[4..].copy_from_slice(&ipv4_bytes);
            let checksum = pnet::packet::icmp::checksum(&packet.to_immutable());
            packet.set_checksum(checksum);
        }
        buffer
    }

    struct SmartReceiver {
        state: Arc<MockState>,
        replies: VecDeque<IpAddr>,
        replied_count: usize,
    }

    impl SmartReceiver {
        fn new(state: Arc<MockState>, replies: Vec<IpAddr>) -> Self {
            Self {
                state,
                replies: VecDeque::from(replies),
                replied_count: 0,
            }
        }
    }

    impl PacketReceiver for SmartReceiver {
        fn next_packet(
            &mut self,
            _timeout: std::time::Duration,
        ) -> Result<Option<(Vec<u8>, IpAddr)>> {
            // Check IPv4 first
            {
                let sent = self.state.sent_v4.lock().unwrap();
                if sent.len() > self.replied_count {
                    let (packet_bytes, _) = &sent[self.replied_count];
                    let packet = IcmpPacket::new(packet_bytes).unwrap();
                    let echo =
                        pnet::packet::icmp::echo_request::EchoRequestPacket::new(packet.packet())
                            .unwrap();
                    let id = echo.get_identifier();
                    let seq = echo.get_sequence_number();

                    if let Some(addr) = self.replies.pop_front() {
                        self.replied_count += 1;
                        let reply = if addr == IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)) {
                            build_icmpv4_echo_reply(id, seq)
                        } else {
                            build_icmpv4_time_exceeded(id, seq)
                        };
                        return Ok(Some((reply, addr)));
                    }
                }
            }
            // Then Check IPv6
            {
                let sent = self.state.sent_v6.lock().unwrap();
                if sent.len() > self.replied_count {
                    let (packet_bytes, _) = &sent[self.replied_count];
                    let packet = Icmpv6Packet::new(packet_bytes).unwrap();
                    let (id, seq) = parse_icmpv6_echo(&packet).unwrap();

                    if let Some(addr) = self.replies.pop_front() {
                        self.replied_count += 1;
                        let reply = if addr == IpAddr::V6(Ipv6Addr::LOCALHOST) {
                            build_icmpv6_echo_reply(id, seq)
                        } else {
                            build_icmpv6_time_exceeded(id, seq)
                        };
                        return Ok(Some((reply, addr)));
                    }
                }
            }
            Ok(None)
        }
    }

    #[test]
    fn test_icmp_v4_traceroute_success() {
        let destination = Ipv4Addr::new(1, 2, 3, 4);
        let opts = TracerouteRequest {
            destination: destination.to_string(),
            max_ttl: 1,
            probes: 1,
            timeout: 100,
            no_dns: Some(true),
            ..Default::default()
        };

        let state = Arc::new(MockState::default());
        let mut sender = MockTransportSender::new(state.clone());
        let mut receiver = SmartReceiver::new(state.clone(), vec![IpAddr::V4(destination)]);

        run_icmp_traceroute_v4_loop(destination, &opts, &mut sender, &mut receiver)
            .expect("traceroute loop");

        assert_eq!(state.sent_v4.lock().unwrap().len(), 1);
        assert_eq!(*state.ttl.lock().unwrap(), Some(1));
    }

    #[test]
    fn test_icmp_v4_traceroute_hop_then_destination() {
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
        let mut sender = MockTransportSender::new(state.clone());
        let mut receiver = SmartReceiver::new(
            state.clone(),
            vec![IpAddr::V4(hop), IpAddr::V4(destination)],
        );

        run_icmp_traceroute_v4_loop(destination, &opts, &mut sender, &mut receiver)
            .expect("traceroute loop");

        assert_eq!(state.sent_v4.lock().unwrap().len(), 2);
        assert_eq!(*state.ttl.lock().unwrap(), Some(2));
    }

    #[test]
    fn test_icmp_v6_traceroute_success() {
        let destination = Ipv6Addr::LOCALHOST;
        let source_ip = Ipv6Addr::LOCALHOST;
        let opts = TracerouteRequest {
            destination: destination.to_string(),
            max_ttl: 1,
            probes: 1,
            timeout: 100,
            no_dns: Some(true),
            ..Default::default()
        };

        let state = Arc::new(MockState::default());
        let mut sender = MockTransportSender::new(state.clone());
        let mut receiver = SmartReceiver::new(state.clone(), vec![IpAddr::V6(destination)]);

        run_icmp_traceroute_v6_loop(destination, source_ip, &opts, &mut sender, &mut receiver)
            .expect("traceroute loop");

        assert_eq!(state.sent_v6.lock().unwrap().len(), 1);
        assert_eq!(*state.ttl.lock().unwrap(), Some(1));
    }

    #[test]
    fn test_icmp_v6_traceroute_hop_then_destination() {
        let destination = Ipv6Addr::LOCALHOST;
        let source_ip = Ipv6Addr::LOCALHOST;
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
        let mut sender = MockTransportSender::new(state.clone());
        let mut receiver = SmartReceiver::new(
            state.clone(),
            vec![IpAddr::V6(hop), IpAddr::V6(destination)],
        );

        run_icmp_traceroute_v6_loop(destination, source_ip, &opts, &mut sender, &mut receiver)
            .expect("traceroute loop");

        assert_eq!(state.sent_v6.lock().unwrap().len(), 2);
        assert_eq!(*state.ttl.lock().unwrap(), Some(2));
    }

    #[test]
    fn test_icmp_v4_traceroute_timeout() {
        let destination = Ipv4Addr::new(1, 2, 3, 4);
        let opts = TracerouteRequest {
            destination: destination.to_string(),
            max_ttl: 1,
            probes: 1,
            timeout: 10, // Short timeout
            no_dns: Some(true),
            ..Default::default()
        };

        let state = Arc::new(MockState::default());
        let mut sender = MockTransportSender::new(state);
        let mut receiver = MockReceiver::new(VecDeque::from(vec![None]));

        run_icmp_traceroute_v4_loop(destination, &opts, &mut sender, &mut receiver)
            .expect("traceroute loop");

        assert_eq!(sender.state.sent_v4.lock().unwrap().len(), 1);
    }
}
