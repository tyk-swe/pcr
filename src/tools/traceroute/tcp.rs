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
    validate_request, PacketReceiver, ProbeIdentity, ProbeResult, TracerouteExecutor,
    TransportSender, TCP_RESPONSE_POLL_INTERVAL,
};
use super::utils::{
    poll_icmp_event_v4_with_source, poll_icmp_event_v6_with_source, IcmpEventKind,
    IcmpReceiverAdapter, Icmpv6ReceiverAdapter, ProbeExpectation,
};

#[derive(Debug, Clone, Copy)]
struct TcpProbeResponse {
    source_port: u16,
    destination_port: u16,
}

trait TcpProbeReceiver {
    fn next_tcp_response(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<(TcpProbeResponse, IpAddr)>>;
}

impl<'a> TcpProbeReceiver for TcpTransportChannelIterator<'a> {
    fn next_tcp_response(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<(TcpProbeResponse, IpAddr)>> {
        Ok(self.next_with_timeout(timeout)?.map(|(packet, addr)| {
            (
                TcpProbeResponse {
                    source_port: packet.get_source(),
                    destination_port: packet.get_destination(),
                },
                addr,
            )
        }))
    }
}

struct TcpV4Executor<'a, S: ?Sized, T: ?Sized, R: ?Sized> {
    destination: Ipv4Addr,
    source_ip: Ipv4Addr,
    timeout: std::time::Duration,
    tcp_sender: &'a mut S,
    tcp_iter: &'a mut T,
    icmp_adapter: &'a mut R,
    base_source_port: u16,
    probes_per_hop: u8,
}

impl<'a, S: ?Sized, T: ?Sized, R: ?Sized> TracerouteExecutor for TcpV4Executor<'a, S, T, R>
where
    S: TransportSender,
    T: TcpProbeReceiver,
    R: PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        let probe = tcp_probe_spec(ttl, probe, self.probes_per_hop, self.base_source_port)?;
        let segment = build_tcp_segment(
            &probe.spec,
            &[],
            IpAddr::V4(self.source_ip),
            IpAddr::V4(self.destination),
        )?;
        let packet = TcpPacket::new(&segment).context(operation_failed(
            "construct TCP packet",
            format!(
                "destination={} source_port={} dest_port={dest_port}",
                self.destination,
                probe.source_port,
                dest_port = probe.destination_port
            ),
        ))?;
        self.tcp_sender.set_ttl(ttl)?;
        self.tcp_sender
            .send_tcp(packet, IpAddr::V4(self.destination))
            .context(operation_failed(
                "send TCP probe",
                format!(
                    "destination={} source_port={} dest_port={dest_port}",
                    self.destination,
                    probe.source_port,
                    dest_port = probe.destination_port
                ),
            ))?;

        await_tcp_probe_v4(
            self.icmp_adapter,
            self.tcp_iter,
            self.source_ip,
            self.destination,
            probe.destination_port,
            probe.source_port,
            self.timeout,
        )
    }
}

pub(super) fn run_tcp_traceroute_v4(
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
    let max_ordinal = validate_request(opts)?.max_ordinal;
    let base_source_port = tcp_base_source_port(max_ordinal)?;

    let mut executor = TcpV4Executor {
        destination,
        source_ip,
        timeout: request_timeout(opts),
        tcp_sender: &mut tcp_sender,
        tcp_iter: &mut tcp_iter,
        icmp_adapter: &mut icmp_adapter,
        base_source_port,
        probes_per_hop: opts.probes,
    };

    run_traceroute_loop_with_delay(opts, &mut executor, send_delay)?;

    // Explicitly drop channels to ensure cleanup
    drop(tcp_sender);

    Ok(())
}

struct TcpV6Executor<'a, S: ?Sized, T: ?Sized, R: ?Sized> {
    destination: Ipv6Addr,
    source_ip: Ipv6Addr,
    timeout: std::time::Duration,
    tcp_sender: &'a mut S,
    tcp_iter: &'a mut T,
    icmp_adapter: &'a mut R,
    base_source_port: u16,
    probes_per_hop: u8,
}

impl<'a, S: ?Sized, T: ?Sized, R: ?Sized> TracerouteExecutor for TcpV6Executor<'a, S, T, R>
where
    S: TransportSender,
    T: TcpProbeReceiver,
    R: PacketReceiver,
{
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
        let probe = tcp_probe_spec(ttl, probe, self.probes_per_hop, self.base_source_port)?;
        let segment = build_tcp_segment(
            &probe.spec,
            &[],
            IpAddr::V6(self.source_ip),
            IpAddr::V6(self.destination),
        )?;
        let packet = TcpPacket::new(&segment).context(operation_failed(
            "construct TCPv6 packet",
            format!(
                "destination={} source_port={} dest_port={dest_port}",
                self.destination,
                probe.source_port,
                dest_port = probe.destination_port
            ),
        ))?;
        self.tcp_sender.set_ttl(ttl)?;
        self.tcp_sender
            .send_tcp(packet, IpAddr::V6(self.destination))
            .context(operation_failed(
                "send TCPv6 probe",
                format!(
                    "destination={} source_port={} dest_port={dest_port}",
                    self.destination,
                    probe.source_port,
                    dest_port = probe.destination_port
                ),
            ))?;

        await_tcp_probe_v6(
            self.icmp_adapter,
            self.tcp_iter,
            self.source_ip,
            self.destination,
            probe.destination_port,
            probe.source_port,
            self.timeout,
        )
    }
}

struct TcpProbeSpec {
    source_port: u16,
    destination_port: u16,
    spec: TcpSpec,
}

fn tcp_probe_spec(
    ttl: u8,
    probe: u8,
    probes_per_hop: u8,
    base_source_port: u16,
) -> Result<TcpProbeSpec> {
    const TCP_WINDOW_SIZE: u16 = 65_535;

    let identity = ProbeIdentity::new(ttl, probe, probes_per_hop)?;
    let destination_port = identity.destination_port()?;
    let source_port = identity.source_port(base_source_port)?;
    let flags = TcpFlagSet {
        syn: true,
        ..Default::default()
    };

    Ok(TcpProbeSpec {
        source_port,
        destination_port,
        spec: TcpSpec {
            source_port: Some(source_port),
            destination_port: Some(destination_port),
            flags,
            sequence: Some(random::<u32>()),
            acknowledgement: Some(0),
            window_size: Some(TCP_WINDOW_SIZE),
            options: None,
        },
    })
}

pub(super) fn run_tcp_traceroute_v6(
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
    let max_ordinal = validate_request(opts)?.max_ordinal;
    let base_source_port = tcp_base_source_port(max_ordinal)?;

    let mut executor = TcpV6Executor {
        destination,
        source_ip,
        timeout: request_timeout(opts),
        tcp_sender: &mut tcp_sender,
        tcp_iter: &mut tcp_iter,
        icmp_adapter: &mut icmp_adapter,
        base_source_port,
        probes_per_hop: opts.probes,
    };

    run_traceroute_loop_with_delay(opts, &mut executor, send_delay)?;

    // Explicitly drop channels to ensure cleanup
    drop(tcp_sender);

    Ok(())
}

fn await_tcp_probe_v4<R, T>(
    icmp_iter: &mut R,
    tcp_iter: &mut T,
    expected_source: Ipv4Addr,
    expected_destination: Ipv4Addr,
    expected_dest_port: u16,
    expected_source_port: u16,
    timeout: Duration,
) -> Result<ProbeResult>
where
    R: PacketReceiver + ?Sized,
    T: TcpProbeReceiver + ?Sized,
{
    let start = Instant::now();
    let expectation = ProbeExpectation::tcp(
        IpNextHeaderProtocols::Tcp,
        IpAddr::V4(expected_source),
        IpAddr::V4(expected_destination),
        expected_source_port,
        expected_dest_port,
    );

    while let Some(remaining) = remaining_probe_time(start, timeout) {
        let (icmp_slice, tcp_slice) = split_tcp_poll_window(remaining);

        if let Some((event, addr)) =
            poll_icmp_event_v4_with_source(icmp_iter, &expectation, icmp_slice)?
        {
            let elapsed = start.elapsed().as_millis();
            return Ok(match event {
                IcmpEventKind::Hop => ProbeResult::Hop(addr, elapsed),
                IcmpEventKind::Destination => ProbeResult::Destination(addr, elapsed),
                IcmpEventKind::TerminalUnreachable(marker) => {
                    ProbeResult::TerminalUnreachable(addr, elapsed, marker)
                }
            });
        }

        if let Some((packet, addr)) = tcp_iter.next_tcp_response(tcp_slice)? {
            if addr == IpAddr::V4(expected_destination)
                && packet.source_port == expected_dest_port
                && packet.destination_port == expected_source_port
            {
                let elapsed = start.elapsed().as_millis();
                return Ok(ProbeResult::Destination(addr, elapsed));
            }
        }
    }
    Ok(ProbeResult::Timeout)
}

fn await_tcp_probe_v6<R, T>(
    icmp_iter: &mut R,
    tcp_iter: &mut T,
    expected_source: Ipv6Addr,
    expected_destination: Ipv6Addr,
    expected_dest_port: u16,
    expected_source_port: u16,
    timeout: Duration,
) -> Result<ProbeResult>
where
    R: PacketReceiver + ?Sized,
    T: TcpProbeReceiver + ?Sized,
{
    let start = Instant::now();
    let expectation = ProbeExpectation::tcp(
        IpNextHeaderProtocols::Tcp,
        IpAddr::V6(expected_source),
        IpAddr::V6(expected_destination),
        expected_source_port,
        expected_dest_port,
    );

    while let Some(remaining) = remaining_probe_time(start, timeout) {
        let (icmp_slice, tcp_slice) = split_tcp_poll_window(remaining);

        if let Some((event, addr)) =
            poll_icmp_event_v6_with_source(icmp_iter, &expectation, icmp_slice)?
        {
            let elapsed = start.elapsed().as_millis();
            return Ok(match event {
                IcmpEventKind::Hop => ProbeResult::Hop(addr, elapsed),
                IcmpEventKind::Destination => ProbeResult::Destination(addr, elapsed),
                IcmpEventKind::TerminalUnreachable(marker) => {
                    ProbeResult::TerminalUnreachable(addr, elapsed, marker)
                }
            });
        }

        if let Some((packet, addr)) = tcp_iter.next_tcp_response(tcp_slice)? {
            if addr == IpAddr::V6(expected_destination)
                && packet.source_port == expected_dest_port
                && packet.destination_port == expected_source_port
            {
                let elapsed = start.elapsed().as_millis();
                return Ok(ProbeResult::Destination(addr, elapsed));
            }
        }
    }
    Ok(ProbeResult::Timeout)
}

fn split_tcp_poll_window(remaining: Duration) -> (Duration, Duration) {
    // Reserve time for both sockets before either blocking read starts.
    let window = remaining.min(TCP_RESPONSE_POLL_INTERVAL);
    let icmp_slice = window / 2;
    if icmp_slice.is_zero() {
        (window, window)
    } else {
        (icmp_slice, window - icmp_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::DEFAULT_PORT;
    use super::*;
    use pnet::packet::tcp::TcpFlags;
    use pnet::packet::Packet;
    use std::collections::VecDeque;

    struct SleepingIcmpReceiver {
        calls: Vec<Duration>,
    }

    impl SleepingIcmpReceiver {
        fn new() -> Self {
            Self { calls: Vec::new() }
        }
    }

    impl PacketReceiver for SleepingIcmpReceiver {
        fn next_packet(&mut self, timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
            self.calls.push(timeout);
            std::thread::sleep(timeout);
            Ok(None)
        }
    }

    struct EmptyIcmpReceiver;

    impl PacketReceiver for EmptyIcmpReceiver {
        fn next_packet(&mut self, _timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
            Ok(None)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TcpSend {
        ttl: u8,
        destination: IpAddr,
        source_port: u16,
        destination_port: u16,
        flags: u8,
    }

    struct MockTcpSender {
        current_ttl: u8,
        sends: Vec<TcpSend>,
    }

    impl MockTcpSender {
        fn new() -> Self {
            Self {
                current_ttl: 0,
                sends: Vec::new(),
            }
        }
    }

    impl TransportSender for MockTcpSender {
        fn set_ttl(&mut self, ttl: u8) -> Result<()> {
            self.current_ttl = ttl;
            Ok(())
        }

        fn send_icmp_v4(
            &mut self,
            _packet: pnet::packet::icmp::IcmpPacket,
            _destination: IpAddr,
        ) -> Result<usize> {
            unreachable!("TCP traceroute tests do not send ICMPv4 packets")
        }

        fn send_icmp_v6(
            &mut self,
            _packet: pnet::packet::icmpv6::Icmpv6Packet,
            _destination: IpAddr,
        ) -> Result<usize> {
            unreachable!("TCP traceroute tests do not send ICMPv6 packets")
        }

        fn send_tcp(&mut self, packet: TcpPacket<'_>, destination: IpAddr) -> Result<usize> {
            self.sends.push(TcpSend {
                ttl: self.current_ttl,
                destination,
                source_port: packet.get_source(),
                destination_port: packet.get_destination(),
                flags: packet.get_flags(),
            });
            Ok(packet.packet().len())
        }
    }

    struct FakeTcpReceiver {
        calls: Vec<Duration>,
        responses: VecDeque<Option<(TcpProbeResponse, IpAddr)>>,
    }

    impl FakeTcpReceiver {
        fn new(responses: impl IntoIterator<Item = Option<(TcpProbeResponse, IpAddr)>>) -> Self {
            Self {
                calls: Vec::new(),
                responses: responses.into_iter().collect(),
            }
        }
    }

    impl TcpProbeReceiver for FakeTcpReceiver {
        fn next_tcp_response(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<(TcpProbeResponse, IpAddr)>> {
            self.calls.push(timeout);
            Ok(self.responses.pop_front().flatten())
        }
    }

    #[test]
    fn tcp_v4_executor_sets_ttl_sends_syn_and_waits_for_tcp_response() {
        let source_ip = Ipv4Addr::new(192, 0, 2, 5);
        let destination = Ipv4Addr::new(192, 0, 2, 10);
        let base_source_port = 45_000;
        let mut sender = MockTcpSender::new();
        let mut icmp = EmptyIcmpReceiver;
        let mut tcp = FakeTcpReceiver::new([Some((
            TcpProbeResponse {
                source_port: DEFAULT_PORT + 3,
                destination_port: base_source_port + 3,
            },
            IpAddr::V4(destination),
        ))]);
        let mut executor = TcpV4Executor {
            destination,
            source_ip,
            timeout: Duration::from_millis(50),
            tcp_sender: &mut sender,
            tcp_iter: &mut tcp,
            icmp_adapter: &mut icmp,
            base_source_port,
            probes_per_hop: 2,
        };

        let result = executor.execute_probe(2, 1).unwrap();

        assert!(matches!(
            result,
            ProbeResult::Destination(IpAddr::V4(addr), _) if addr == destination
        ));
        assert_eq!(
            executor.tcp_sender.sends,
            vec![TcpSend {
                ttl: 2,
                destination: IpAddr::V4(destination),
                source_port: base_source_port + 3,
                destination_port: DEFAULT_PORT + 3,
                flags: TcpFlags::SYN,
            }]
        );
        assert_eq!(executor.tcp_iter.calls.len(), 1);
    }

    #[test]
    fn tcp_v6_executor_sets_ttl_sends_syn_and_waits_for_tcp_response() {
        let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let base_source_port = 46_000;
        let mut sender = MockTcpSender::new();
        let mut icmp = EmptyIcmpReceiver;
        let mut tcp = FakeTcpReceiver::new([Some((
            TcpProbeResponse {
                source_port: DEFAULT_PORT,
                destination_port: base_source_port,
            },
            IpAddr::V6(destination),
        ))]);
        let mut executor = TcpV6Executor {
            destination,
            source_ip,
            timeout: Duration::from_millis(50),
            tcp_sender: &mut sender,
            tcp_iter: &mut tcp,
            icmp_adapter: &mut icmp,
            base_source_port,
            probes_per_hop: 2,
        };

        let result = executor.execute_probe(1, 0).unwrap();

        assert!(matches!(
            result,
            ProbeResult::Destination(IpAddr::V6(addr), _) if addr == destination
        ));
        assert_eq!(
            executor.tcp_sender.sends,
            vec![TcpSend {
                ttl: 1,
                destination: IpAddr::V6(destination),
                source_port: base_source_port,
                destination_port: DEFAULT_PORT,
                flags: TcpFlags::SYN,
            }]
        );
        assert_eq!(executor.tcp_iter.calls.len(), 1);
    }

    #[test]
    fn await_tcp_probe_v4_checks_tcp_after_icmp_uses_reserved_final_slice() {
        let expected_source = Ipv4Addr::new(192, 0, 2, 10);
        let expected_destination = Ipv4Addr::new(198, 51, 100, 20);
        let expected_dest_port = 33_434;
        let expected_source_port = 45_000;
        let mut icmp = SleepingIcmpReceiver::new();
        let mut tcp = FakeTcpReceiver::new([Some((
            TcpProbeResponse {
                source_port: expected_dest_port,
                destination_port: expected_source_port,
            },
            IpAddr::V4(expected_destination),
        ))]);

        let result = await_tcp_probe_v4(
            &mut icmp,
            &mut tcp,
            expected_source,
            expected_destination,
            expected_dest_port,
            expected_source_port,
            Duration::from_millis(4),
        )
        .unwrap();

        assert!(matches!(
            result,
            ProbeResult::Destination(IpAddr::V4(addr), _) if addr == expected_destination
        ));
        assert_eq!(icmp.calls.len(), 1);
        assert_eq!(tcp.calls.len(), 1);
        assert!(icmp.calls[0] < Duration::from_millis(4));
        assert!(!tcp.calls[0].is_zero());
    }

    #[test]
    fn await_tcp_probe_v6_checks_tcp_after_icmp_uses_reserved_final_slice() {
        let expected_source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let expected_destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20);
        let expected_dest_port = 33_434;
        let expected_source_port = 45_000;
        let mut icmp = SleepingIcmpReceiver::new();
        let mut tcp = FakeTcpReceiver::new([Some((
            TcpProbeResponse {
                source_port: expected_dest_port,
                destination_port: expected_source_port,
            },
            IpAddr::V6(expected_destination),
        ))]);

        let result = await_tcp_probe_v6(
            &mut icmp,
            &mut tcp,
            expected_source,
            expected_destination,
            expected_dest_port,
            expected_source_port,
            Duration::from_millis(4),
        )
        .unwrap();

        assert!(matches!(
            result,
            ProbeResult::Destination(IpAddr::V6(addr), _) if addr == expected_destination
        ));
        assert_eq!(icmp.calls.len(), 1);
        assert_eq!(tcp.calls.len(), 1);
        assert!(icmp.calls[0] < Duration::from_millis(4));
        assert!(!tcp.calls[0].is_zero());
    }
}
