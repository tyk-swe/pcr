// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::anyhow;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::domain::command::TracerouteRequest;
use crate::util::error::operation_failed;
use anyhow::{Context, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter};

use super::common::{
    open_ipv4_channel, open_ipv6_channel, request_timeout, run_traceroute_loop_with_delay,
    PacketReceiver, ProbeResult, TracerouteExecutor, UdpSocketV4, UdpSocketV6, DEFAULT_PORT,
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

pub(super) fn run_udp_traceroute_v4(
    destination: Ipv4Addr,
    opts: &TracerouteRequest,
    send_delay: Option<std::time::Duration>,
) -> Result<()> {
    let bind_addr = (Ipv4Addr::UNSPECIFIED, 0);
    let socket = std::net::UdpSocket::bind(bind_addr)
        .with_context(|| operation_failed("bind UDP socket", format!("addr={bind_addr:?}")))?;

    let (sender, mut receiver) =
        open_ipv4_channel(IpNextHeaderProtocols::Icmp, "open ICMP channel")?;

    // Drop unused ICMP sender to release resources early
    drop(sender);

    let mut iter = icmp_packet_iter(&mut receiver);
    let mut adapter = IcmpReceiverAdapter(&mut iter);

    run_udp_traceroute_v4_loop_with_delay(destination, opts, send_delay, &socket, &mut adapter)?;

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

fn run_udp_traceroute_v4_loop_with_delay<S, R>(
    destination: Ipv4Addr,
    opts: &TracerouteRequest,
    send_delay: Option<std::time::Duration>,
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
    run_traceroute_loop_with_delay(opts, &mut executor, send_delay)
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

fn run_udp_traceroute_v6_loop_with_delay<S, R>(
    destination: Ipv6Addr,
    opts: &TracerouteRequest,
    send_delay: Option<std::time::Duration>,
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
    run_traceroute_loop_with_delay(opts, &mut executor, send_delay)
}

pub(super) fn run_udp_traceroute_v6(
    destination: Ipv6Addr,
    opts: &TracerouteRequest,
    send_delay: Option<std::time::Duration>,
) -> Result<()> {
    let bind_addr = (Ipv6Addr::UNSPECIFIED, 0);
    let socket = std::net::UdpSocket::bind(bind_addr)
        .with_context(|| operation_failed("bind IPv6 UDP socket", format!("addr={bind_addr:?}")))?;

    let (sender, mut receiver) =
        open_ipv6_channel(IpNextHeaderProtocols::Icmpv6, "open ICMPv6 channel")?;

    // Drop unused ICMPv6 sender to release resources early
    drop(sender);

    let mut iter = icmpv6_packet_iter(&mut receiver);
    let mut adapter = Icmpv6ReceiverAdapter(&mut iter);

    run_udp_traceroute_v6_loop_with_delay(destination, opts, send_delay, &socket, &mut adapter)?;

    // Explicitly drop channels to ensure cleanup
    drop(socket);

    Ok(())
}
