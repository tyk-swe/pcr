// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::transport::{
    icmp_packet_iter, icmpv6_packet_iter, tcp_packet_iter, TcpTransportChannelIterator,
};
use rand::random;

use crate::domain::command::TracerouteRequest;
use crate::domain::spec::{TcpFlagSet, TcpSpec};
use crate::network::sender::build_tcp_segment;
use crate::util::error::operation_failed;

use super::common::{
    open_ipv4_channel, open_ipv6_channel, remaining_probe_time, request_timeout,
    resolve_source_ipv4, resolve_source_ipv6, run_traceroute_loop_with_delay, tcp_base_source_port,
    PacketReceiver, ProbeResult, TracerouteExecutor, DEFAULT_PORT,
};
use super::utils::{
    poll_icmp_event_v4_with_source, poll_icmp_event_v6_with_source, IcmpEventKind,
    IcmpReceiverAdapter, Icmpv6ReceiverAdapter,
};

struct TcpV4Executor<'a, R: ?Sized> {
    destination: Ipv4Addr,
    source_ip: Ipv4Addr,
    timeout: std::time::Duration,
    tcp_sender: &'a mut pnet::transport::TransportSender,
    tcp_iter: &'a mut pnet::transport::TcpTransportChannelIterator<'a>,
    icmp_adapter: &'a mut R,
    base_source_port: u16,
}

impl<'a, R: ?Sized> TracerouteExecutor for TcpV4Executor<'a, R>
where
    R: PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        // Maintain unique tuple per probe to reliably interpret mixed ICMP and TCP responses.
        let dest_port_offset = (ttl as u16).wrapping_mul(3).wrapping_add(probe as u16);
        let dest_port = DEFAULT_PORT.wrapping_add(dest_port_offset);
        let source_port_offset = (ttl as u16).wrapping_mul(8).wrapping_add(probe as u16);
        let source_port = self.base_source_port.wrapping_add(source_port_offset);
        let flags = TcpFlagSet {
            syn: true,
            ..Default::default()
        };
        let spec = TcpSpec {
            source_port: Some(source_port),
            destination_port: Some(dest_port),
            flags,
            sequence: Some(random::<u32>()),
            acknowledgement: Some(0),
            window_size: Some(65_535),
            options: None,
        };
        let segment = build_tcp_segment(
            &spec,
            &[],
            IpAddr::V4(self.source_ip),
            IpAddr::V4(self.destination),
        )?;
        let packet = TcpPacket::new(&segment).context(operation_failed(
            "construct TCP packet",
            format!(
                "destination={} source_port={} dest_port={dest_port}",
                self.destination, source_port
            ),
        ))?;
        self.tcp_sender.set_ttl(ttl)?;
        self.tcp_sender
            .send_to(packet, IpAddr::V4(self.destination))
            .context(operation_failed(
                "send TCP probe",
                format!(
                    "destination={} source_port={} dest_port={dest_port}",
                    self.destination, source_port
                ),
            ))?;

        await_tcp_probe_v4(
            self.icmp_adapter,
            self.tcp_iter,
            self.destination,
            dest_port,
            source_port,
            self.timeout,
        )
    }
}

pub fn run_tcp_traceroute_v4(
    destination: Ipv4Addr,
    opts: &TracerouteRequest,
    send_delay: Option<Duration>,
) -> Result<()> {
    let source_ip = resolve_source_ipv4(destination)?;
    let (mut tcp_sender, mut tcp_receiver) =
        open_ipv4_channel(IpNextHeaderProtocols::Tcp, "open TCP transport channel")?;
    let (icmp_sender, mut icmp_receiver) =
        open_ipv4_channel(IpNextHeaderProtocols::Icmp, "open ICMP channel")?;

    // Drop unused ICMP sender to release resources early
    drop(icmp_sender);

    let mut icmp_iter = icmp_packet_iter(&mut icmp_receiver);
    let mut icmp_adapter = IcmpReceiverAdapter(&mut icmp_iter);

    let mut tcp_iter = tcp_packet_iter(&mut tcp_receiver);
    let base_source_port = tcp_base_source_port();

    let mut executor = TcpV4Executor {
        destination,
        source_ip,
        timeout: request_timeout(opts),
        tcp_sender: &mut tcp_sender,
        tcp_iter: &mut tcp_iter,
        icmp_adapter: &mut icmp_adapter,
        base_source_port,
    };

    run_traceroute_loop_with_delay(opts, &mut executor, send_delay)?;

    // Explicitly drop channels to ensure cleanup
    drop(tcp_sender);

    Ok(())
}

struct TcpV6Executor<'a, R: ?Sized> {
    destination: Ipv6Addr,
    source_ip: Ipv6Addr,
    timeout: std::time::Duration,
    tcp_sender: &'a mut pnet::transport::TransportSender,
    tcp_iter: &'a mut pnet::transport::TcpTransportChannelIterator<'a>,
    icmp_adapter: &'a mut R,
    base_source_port: u16,
}

impl<'a, R: ?Sized> TracerouteExecutor for TcpV6Executor<'a, R>
where
    R: PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        let dest_port_offset = (ttl as u16).wrapping_mul(3).wrapping_add(probe as u16);
        let dest_port = DEFAULT_PORT.wrapping_add(dest_port_offset);
        let source_port_offset = (ttl as u16).wrapping_mul(8).wrapping_add(probe as u16);
        let source_port = self.base_source_port.wrapping_add(source_port_offset);
        let flags = TcpFlagSet {
            syn: true,
            ..Default::default()
        };
        let spec = TcpSpec {
            source_port: Some(source_port),
            destination_port: Some(dest_port),
            flags,
            sequence: Some(random::<u32>()),
            acknowledgement: Some(0),
            window_size: Some(65_535),
            options: None,
        };
        let segment = build_tcp_segment(
            &spec,
            &[],
            IpAddr::V6(self.source_ip),
            IpAddr::V6(self.destination),
        )?;
        let packet = TcpPacket::new(&segment).context(operation_failed(
            "construct TCPv6 packet",
            format!(
                "destination={} source_port={} dest_port={dest_port}",
                self.destination, source_port
            ),
        ))?;
        self.tcp_sender.set_ttl(ttl)?;
        self.tcp_sender
            .send_to(packet, IpAddr::V6(self.destination))
            .context(operation_failed(
                "send TCPv6 probe",
                format!(
                    "destination={} source_port={} dest_port={dest_port}",
                    self.destination, source_port
                ),
            ))?;

        await_tcp_probe_v6(
            self.icmp_adapter,
            self.tcp_iter,
            self.destination,
            dest_port,
            source_port,
            self.timeout,
        )
    }
}

pub fn run_tcp_traceroute_v6(
    destination: Ipv6Addr,
    opts: &TracerouteRequest,
    send_delay: Option<Duration>,
) -> Result<()> {
    let source_ip = resolve_source_ipv6(destination)?;
    let (mut tcp_sender, mut tcp_receiver) =
        open_ipv6_channel(IpNextHeaderProtocols::Tcp, "open TCPv6 transport channel")?;
    let (icmp_sender, mut icmp_receiver) =
        open_ipv6_channel(IpNextHeaderProtocols::Icmpv6, "open ICMPv6 channel")?;

    // Drop unused ICMPv6 sender to release resources early
    drop(icmp_sender);

    let mut icmp_iter = icmpv6_packet_iter(&mut icmp_receiver);
    let mut icmp_adapter = Icmpv6ReceiverAdapter(&mut icmp_iter);

    let mut tcp_iter = tcp_packet_iter(&mut tcp_receiver);
    let base_source_port = tcp_base_source_port();

    let mut executor = TcpV6Executor {
        destination,
        source_ip,
        timeout: request_timeout(opts),
        tcp_sender: &mut tcp_sender,
        tcp_iter: &mut tcp_iter,
        icmp_adapter: &mut icmp_adapter,
        base_source_port,
    };

    run_traceroute_loop_with_delay(opts, &mut executor, send_delay)?;

    // Explicitly drop channels to ensure cleanup
    drop(tcp_sender);

    Ok(())
}

fn await_tcp_probe_v4<R: PacketReceiver + ?Sized>(
    icmp_iter: &mut R,
    tcp_iter: &mut TcpTransportChannelIterator,
    expected_destination: Ipv4Addr,
    expected_dest_port: u16,
    expected_source_port: u16,
    timeout: Duration,
) -> Result<ProbeResult> {
    let start = Instant::now();
    while let Some(remaining) = remaining_probe_time(start, timeout) {
        let slice = remaining.min(Duration::from_millis(100));

        if let Some((event, addr)) = poll_icmp_event_v4_with_source(
            icmp_iter,
            IpNextHeaderProtocols::Tcp,
            Some(expected_source_port),
            expected_dest_port,
            None,
            slice,
        )? {
            let elapsed = start.elapsed().as_millis();
            return Ok(match event {
                IcmpEventKind::Hop => ProbeResult::Hop(addr, elapsed),
                IcmpEventKind::Destination => ProbeResult::Destination(addr, elapsed),
            });
        }

        if let Some((packet, addr)) = tcp_iter.next_with_timeout(slice)? {
            if addr == IpAddr::V4(expected_destination)
                && packet.get_source() == expected_dest_port
                && packet.get_destination() == expected_source_port
            {
                let elapsed = start.elapsed().as_millis();
                return Ok(ProbeResult::Destination(addr, elapsed));
            }
        }
    }
    Ok(ProbeResult::Timeout)
}

fn await_tcp_probe_v6<R: PacketReceiver + ?Sized>(
    icmp_iter: &mut R,
    tcp_iter: &mut TcpTransportChannelIterator,
    expected_destination: Ipv6Addr,
    expected_dest_port: u16,
    expected_source_port: u16,
    timeout: Duration,
) -> Result<ProbeResult> {
    let start = Instant::now();
    while let Some(remaining) = remaining_probe_time(start, timeout) {
        let slice = remaining.min(Duration::from_millis(100));

        if let Some((event, addr)) = poll_icmp_event_v6_with_source(
            icmp_iter,
            IpNextHeaderProtocols::Tcp,
            Some(expected_source_port),
            expected_dest_port,
            None,
            slice,
        )? {
            let elapsed = start.elapsed().as_millis();
            return Ok(match event {
                IcmpEventKind::Hop => ProbeResult::Hop(addr, elapsed),
                IcmpEventKind::Destination => ProbeResult::Destination(addr, elapsed),
            });
        }

        if let Some((packet, addr)) = tcp_iter.next_with_timeout(slice)? {
            if addr == IpAddr::V6(expected_destination)
                && packet.get_source() == expected_dest_port
                && packet.get_destination() == expected_source_port
            {
                let elapsed = start.elapsed().as_millis();
                return Ok(ProbeResult::Destination(addr, elapsed));
            }
        }
    }
    Ok(ProbeResult::Timeout)
}
