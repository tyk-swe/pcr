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
    run_traceroute_loop_with_delay, PacketReceiver, ProbeResult, TracerouteExecutor,
    TransportSender,
};
use super::utils::{
    await_icmp_echo_v4, await_icmpv6_echo, build_echo_request, IcmpReceiverAdapter,
    Icmpv6ReceiverAdapter,
};

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
