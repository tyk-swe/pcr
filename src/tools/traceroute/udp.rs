// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::domain::command::TracerouteRequest;
use crate::util::error::operation_failed;
use anyhow::{Context, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter};

use super::common::{
    open_ipv4_channel, open_ipv6_channel, request_timeout, run_traceroute_loop_with_delay,
    udp_run_cookie, PacketReceiver, ProbeIdentity, ProbeResult, TracerouteExecutor, UdpProbeCookie,
    UdpSocketV4, UdpSocketV6,
};
use super::utils::{
    await_icmp_response_v4, await_icmp_response_v6, IcmpReceiverAdapter, Icmpv6ReceiverAdapter,
    ProbeExpectation,
};

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
    probes_per_hop: u8,
    source_port: u16,
    run_cookie: u64,
}

impl<'a, S, R: ?Sized> TracerouteExecutor for UdpV4Executor<'a, S, R>
where
    S: UdpSocketV4,
    R: super::common::PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        let identity = ProbeIdentity::new(ttl, probe, self.probes_per_hop)?;
        let port = identity.destination_port()?;
        let cookie = UdpProbeCookie::new(self.run_cookie, identity);
        self.socket.set_ttl(ttl as u32)?;
        self.socket
            .send_to(&cookie.bytes(), (self.destination, port))
            .with_context(|| {
                operation_failed(
                    "send UDP probe",
                    format!("destination={} port={port}", self.destination),
                )
            })?;

        let expectation = ProbeExpectation::udp(
            IpNextHeaderProtocols::Udp,
            None,
            IpAddr::V4(self.destination),
            Some(self.source_port),
            port,
            cookie,
        );
        await_icmp_response_v4(self.receiver, &expectation, self.timeout)
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
    let source_port = socket.local_addr()?.port();
    let mut executor = UdpV4Executor {
        destination,
        timeout: request_timeout(opts),
        socket,
        receiver,
        probes_per_hop: opts.probes,
        source_port,
        run_cookie: udp_run_cookie(),
    };
    run_traceroute_loop_with_delay(opts, &mut executor, send_delay)
}

struct UdpV6Executor<'a, S, R: ?Sized> {
    destination: Ipv6Addr,
    timeout: std::time::Duration,
    socket: &'a S,
    receiver: &'a mut R,
    probes_per_hop: u8,
    source_port: u16,
    run_cookie: u64,
}

impl<'a, S, R: ?Sized> TracerouteExecutor for UdpV6Executor<'a, S, R>
where
    S: UdpSocketV6,
    R: PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        let identity = ProbeIdentity::new(ttl, probe, self.probes_per_hop)?;
        let port = identity.destination_port()?;
        let cookie = UdpProbeCookie::new(self.run_cookie, identity);
        self.socket.set_unicast_hops_v6(u32::from(ttl))?;
        self.socket
            .send_to(&cookie.bytes(), (self.destination, port))
            .with_context(|| {
                operation_failed(
                    "send IPv6 UDP probe",
                    format!("destination={} port={port}", self.destination),
                )
            })?;

        let expectation = ProbeExpectation::udp(
            IpNextHeaderProtocols::Udp,
            None,
            IpAddr::V6(self.destination),
            Some(self.source_port),
            port,
            cookie,
        );
        await_icmp_response_v6(self.receiver, &expectation, self.timeout)
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
    let source_port = socket.local_addr()?.port();
    let mut executor = UdpV6Executor {
        destination,
        timeout: request_timeout(opts),
        socket,
        receiver,
        probes_per_hop: opts.probes,
        source_port,
        run_cookie: udp_run_cookie(),
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
