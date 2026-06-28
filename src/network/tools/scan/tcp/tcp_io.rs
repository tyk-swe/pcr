// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pnet::transport::{
    IcmpTransportChannelIterator, Icmpv6TransportChannelIterator, TcpTransportChannelIterator,
    TransportSender,
};
use socket2::{SockAddr, Socket};

use crate::network::protocol_validation::{
    extract_original_transport_v4, extract_original_transport_v6,
};

use super::super::common::{send_with_enobufs_retry, ScanEvent};

const PACKET_POLL_INTERVAL: Duration = Duration::from_millis(1);

pub(super) trait TcpSender: Send {
    fn send_tcp(&mut self, packet: TcpPacket<'_>, destination: SocketAddr) -> Result<()>;
}

pub(super) struct RealTcpSender<'a>(pub(super) &'a mut TransportSender);

impl<'a> TcpSender for RealTcpSender<'a> {
    fn send_tcp(&mut self, packet: TcpPacket<'_>, destination: SocketAddr) -> Result<()> {
        send_tcp_with_retry(packet.packet(), destination, |packet, dest| {
            self.0.send_to(packet, dest.ip()).map(|_| ())
        })
    }
}

pub(super) struct RawSocketSender {
    pub(super) socket: Socket,
}

impl TcpSender for RawSocketSender {
    fn send_tcp(&mut self, packet: TcpPacket<'_>, destination: SocketAddr) -> Result<()> {
        let dest_addr = SockAddr::from(destination);
        send_tcp_with_retry(packet.packet(), destination, |packet, _| {
            self.socket.send_to(packet.packet(), &dest_addr).map(|_| ())
        })
    }
}

pub(super) fn send_tcp_with_retry<F>(
    packet_bytes: &[u8],
    destination: SocketAddr,
    mut send_fn: F,
) -> Result<()>
where
    F: FnMut(TcpPacket<'_>, SocketAddr) -> std::io::Result<()>,
{
    if TcpPacket::new(packet_bytes).is_none() {
        return Err(anyhow!(
            "rebuild TCP packet failed: destination={}",
            destination
        ));
    }

    send_with_enobufs_retry("send TCP probe", destination, || {
        let packet = TcpPacket::new(packet_bytes).expect("TCP packet bytes validated before retry");
        send_fn(packet, destination)
    })
}

pub(super) trait TcpScanRx {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<ScanEvent>>;
}

pub(super) struct RealTcpRxV4<'a> {
    pub(super) tcp_iter: TcpTransportChannelIterator<'a>,
    pub(super) icmp_iter: IcmpTransportChannelIterator<'a>,
}

impl<'a> TcpScanRx for RealTcpRxV4<'a> {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<ScanEvent>> {
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout {
                return Ok(None);
            }

            if let Some((packet, addr)) = self.tcp_iter.next_with_timeout(PACKET_POLL_INTERVAL)? {
                return Ok(Some(ScanEvent::PacketResponse {
                    source_port: packet.get_source(),
                    dest_port: packet.get_destination(),
                    flags: Some(packet.get_flags()),
                    src_addr: addr,
                }));
            }

            if let Some((packet, _)) = self.icmp_iter.next_with_timeout(PACKET_POLL_INTERVAL)? {
                if let Some(transport) = extract_original_transport_v4(&packet) {
                    if transport.protocol == IpNextHeaderProtocols::Tcp {
                        return Ok(Some(ScanEvent::icmp_response(
                            transport,
                            packet.get_icmp_type().0,
                            packet.get_icmp_code().0,
                        )));
                    }
                }
            }
        }
    }
}

pub(super) struct RealTcpRxV6<'a> {
    pub(super) tcp_iter: TcpTransportChannelIterator<'a>,
    pub(super) icmp_iter: Icmpv6TransportChannelIterator<'a>,
}

impl<'a> TcpScanRx for RealTcpRxV6<'a> {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<ScanEvent>> {
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout {
                return Ok(None);
            }

            if let Some((packet, addr)) = self.tcp_iter.next_with_timeout(PACKET_POLL_INTERVAL)? {
                return Ok(Some(ScanEvent::PacketResponse {
                    source_port: packet.get_source(),
                    dest_port: packet.get_destination(),
                    flags: Some(packet.get_flags()),
                    src_addr: addr,
                }));
            }

            if let Some((packet, _)) = self.icmp_iter.next_with_timeout(PACKET_POLL_INTERVAL)? {
                if let Some(transport) = extract_original_transport_v6(&packet) {
                    if transport.protocol == IpNextHeaderProtocols::Tcp {
                        return Ok(Some(ScanEvent::icmp_response(
                            transport,
                            packet.get_icmpv6_type().0,
                            packet.get_icmpv6_code().0,
                        )));
                    }
                }
            }
        }
    }
}
