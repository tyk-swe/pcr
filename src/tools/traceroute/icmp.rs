// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter};
use rand::random;

use crate::domain::command::TracerouteRequest;
use crate::domain::spec::Icmpv6Spec;
use crate::network::sender::build_icmpv6_segment;
use crate::util::error::operation_failed;

use super::common::{
    open_ipv4_channel, open_ipv6_channel, request_timeout, resolve_source_ipv6,
    run_traceroute_loop_with_delay, PacketReceiver, ProbeIdentity, ProbeResult, TracerouteExecutor,
    TransportSender,
};
use super::utils::{
    await_icmp_echo_v4, await_icmpv6_echo, build_echo_request, IcmpReceiverAdapter,
    Icmpv6ReceiverAdapter, ProbeExpectation,
};

struct IcmpV4Executor<'a, S, R: ?Sized> {
    destination: Ipv4Addr,
    timeout: std::time::Duration,
    sender: &'a mut S,
    receiver: &'a mut R,
    identifier: u16,
    probes_per_hop: u8,
}

impl<'a, S, R: ?Sized> TracerouteExecutor for IcmpV4Executor<'a, S, R>
where
    S: TransportSender,
    R: PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        let identity = ProbeIdentity::new(ttl, probe, self.probes_per_hop)?;
        let sequence = identity.ordinal();
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

        let expectation = ProbeExpectation::icmp(
            IpNextHeaderProtocols::Icmp,
            None,
            IpAddr::V4(self.destination),
            self.identifier,
            sequence,
        );
        await_icmp_echo_v4(self.receiver, &expectation, self.timeout)
    }
}

pub(super) fn run_icmp_traceroute_v4(
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
        probes_per_hop: opts.probes,
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
    probes_per_hop: u8,
}

impl<'a, S, R: ?Sized> TracerouteExecutor for IcmpV6Executor<'a, S, R>
where
    S: TransportSender,
    R: PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        let identity = ProbeIdentity::new(ttl, probe, self.probes_per_hop)?;
        let sequence = identity.ordinal();
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

        let expectation = ProbeExpectation::icmp(
            IpNextHeaderProtocols::Icmpv6,
            Some(IpAddr::V6(self.source_ip)),
            IpAddr::V6(self.destination),
            self.identifier,
            sequence,
        );
        await_icmpv6_echo(self.receiver, &expectation, self.timeout)
    }
}

pub(super) fn run_icmp_traceroute_v6(
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
        probes_per_hop: opts.probes,
    };

    run_traceroute_loop_with_delay(opts, &mut executor, send_delay)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use pnet::packet::icmp::echo_request::EchoRequestPacket;
    use pnet::packet::Packet;

    use crate::domain::command::TracerouteProtocol;

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct EchoSend {
        ttl: u8,
        destination: IpAddr,
        identifier: u16,
        sequence: u16,
    }

    struct MockTransportSender {
        current_ttl: u8,
        v4_sends: Vec<EchoSend>,
        v6_sends: Vec<EchoSend>,
    }

    impl MockTransportSender {
        fn new() -> Self {
            Self {
                current_ttl: 0,
                v4_sends: Vec::new(),
                v6_sends: Vec::new(),
            }
        }
    }

    impl TransportSender for MockTransportSender {
        fn set_ttl(&mut self, ttl: u8) -> Result<()> {
            self.current_ttl = ttl;
            Ok(())
        }

        fn send_icmp_v4(&mut self, packet: IcmpPacket, destination: IpAddr) -> Result<usize> {
            let echo = EchoRequestPacket::new(packet.packet()).expect("test echo request packet");
            self.v4_sends.push(EchoSend {
                ttl: self.current_ttl,
                destination,
                identifier: echo.get_identifier(),
                sequence: echo.get_sequence_number(),
            });
            Ok(packet.packet().len())
        }

        fn send_icmp_v6(&mut self, packet: Icmpv6Packet, destination: IpAddr) -> Result<usize> {
            let bytes = packet.packet();
            self.v6_sends.push(EchoSend {
                ttl: self.current_ttl,
                destination,
                identifier: u16::from_be_bytes([bytes[4], bytes[5]]),
                sequence: u16::from_be_bytes([bytes[6], bytes[7]]),
            });
            Ok(bytes.len())
        }

        fn send_tcp(
            &mut self,
            _packet: pnet::packet::tcp::TcpPacket<'_>,
            _destination: IpAddr,
        ) -> Result<usize> {
            unreachable!("ICMP traceroute tests do not send TCP packets")
        }
    }

    struct EmptyReceiver;

    impl PacketReceiver for EmptyReceiver {
        fn next_packet(&mut self, _timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
            Ok(None)
        }
    }

    fn request(max_ttl: u8, probes: u8) -> TracerouteRequest {
        TracerouteRequest {
            destination: "example.test".to_string(),
            max_ttl,
            probes,
            protocol: TracerouteProtocol::Icmp,
            no_dns: Some(true),
            timeout: 0,
        }
    }

    #[test]
    fn icmp_v4_executor_sets_ttl_and_sequences_echo_requests() {
        let destination = Ipv4Addr::new(192, 0, 2, 10);
        let mut sender = MockTransportSender::new();
        let mut receiver = EmptyReceiver;

        run_icmp_traceroute_v4_loop_with_delay(
            destination,
            &request(1, 2),
            None,
            &mut sender,
            &mut receiver,
        )
        .unwrap();

        assert_eq!(sender.v4_sends.len(), 2);
        assert_eq!(sender.v4_sends[0].ttl, 1);
        assert_eq!(sender.v4_sends[0].destination, IpAddr::V4(destination));
        assert_eq!(sender.v4_sends[0].sequence, 0);
        assert_eq!(sender.v4_sends[1].ttl, 1);
        assert_eq!(sender.v4_sends[1].destination, IpAddr::V4(destination));
        assert_eq!(sender.v4_sends[1].sequence, 1);
        assert_eq!(sender.v4_sends[0].identifier, sender.v4_sends[1].identifier);
    }

    #[test]
    fn icmp_v6_executor_sets_ttl_and_sequences_echo_requests() {
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        let mut sender = MockTransportSender::new();
        let mut receiver = EmptyReceiver;

        run_icmp_traceroute_v6_loop_with_delay(
            destination,
            source_ip,
            &request(1, 2),
            None,
            &mut sender,
            &mut receiver,
        )
        .unwrap();

        assert_eq!(sender.v6_sends.len(), 2);
        assert_eq!(sender.v6_sends[0].ttl, 1);
        assert_eq!(sender.v6_sends[0].destination, IpAddr::V6(destination));
        assert_eq!(sender.v6_sends[0].sequence, 0);
        assert_eq!(sender.v6_sends[1].ttl, 1);
        assert_eq!(sender.v6_sends[1].destination, IpAddr::V6(destination));
        assert_eq!(sender.v6_sends[1].sequence, 1);
        assert_eq!(sender.v6_sends[0].identifier, sender.v6_sends[1].identifier);
    }
}
