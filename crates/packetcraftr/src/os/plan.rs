// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use bytes::Bytes;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::{
    BuiltinProtocol,
    network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
    transport::{Tcp, TcpOption},
};

use super::Probe;

#[derive(Clone, Debug)]
pub(super) struct PlannedProbe {
    pub sequence: u64,
    pub attempt: u32,
    pub address: IpAddr,
    pub interface: Option<packetcraftr_netio::interface::Id>,
    pub port: u16,
    pub source_port: u16,
    pub identity: u32,
    pub kind: Option<Probe>,
    pub cleanup_ack: u32,
}

impl crate::probe::runner::Sequenced for PlannedProbe {
    fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl PlannedProbe {
    pub(super) fn packet(&self) -> Packet {
        let mut packet = Packet::new();
        match self.address {
            IpAddr::V4(destination) => packet.push(Ipv4 {
                destination,
                ttl: 64,
                identification: crate::engine::correlation::nonzero_ipv4_identification(u64::from(
                    self.identity,
                )),
                dont_fragment: true,
                ..Ipv4::default()
            }),
            IpAddr::V6(destination) => packet.push(Ipv6 {
                destination,
                hop_limit: 64,
                ..Ipv6::default()
            }),
        };
        if self.kind == Some(Probe::Echo) {
            let mut body =
                crate::engine::correlation::icmp_identity(0x4f, u64::from(self.identity)).to_vec();
            body.extend_from_slice(&self.identity.to_be_bytes());
            match self.address {
                IpAddr::V4(_) => packet.push(Icmpv4 {
                    body: Bytes::from(body),
                    ..Icmpv4::default()
                }),
                IpAddr::V6(_) => packet.push(Icmpv6 {
                    body: Bytes::from(body),
                    ..Icmpv6::default()
                }),
            };
        } else {
            let mut options = Vec::new();
            if matches!(self.kind, Some(Probe::OpenSyn | Probe::TimestampSyn)) {
                options = vec![
                    TcpOption::Mss(1460),
                    TcpOption::SackPermitted,
                    TcpOption::Nop,
                    TcpOption::WindowScale(7),
                ];
                if self.kind == Some(Probe::TimestampSyn) {
                    options.push(TcpOption::Timestamps {
                        value: self.identity,
                        echo_reply: 0,
                    });
                } else {
                    // Author the encoder's two alignment bytes explicitly so
                    // final-wire verification compares the same representation.
                    options.push(TcpOption::End);
                    options.push(TcpOption::Trailing(Bytes::from_static(&[0])));
                }
            }
            packet.push(Tcp {
                source_port: self.source_port,
                destination_port: self.port,
                sequence: self.identity,
                acknowledgment: self.cleanup_ack,
                flags: if self.kind.is_some() {
                    Tcp::SYN
                } else {
                    Tcp::RST | Tcp::ACK
                },
                window: if self.kind.is_some() { 65535 } else { 0 },
                options,
                ..Tcp::default()
            });
        }
        packet
    }

    /// Route preparation may fill source/link fields and checksums. Every other
    /// probe field is checked against the authored packet before it is trusted.
    pub(super) fn sent_matches(&self, sent: &Packet) -> bool {
        let network = if self.address.is_ipv4() {
            BuiltinProtocol::Ipv4
        } else {
            BuiltinProtocol::Ipv6
        };
        let transport = if self.kind == Some(Probe::Echo) {
            if self.address.is_ipv4() {
                BuiltinProtocol::Icmpv4
            } else {
                BuiltinProtocol::Icmpv6
            }
        } else {
            BuiltinProtocol::Tcp
        };
        if !crate::engine::correlation::packet_shape_matches(sent, &[network, transport]) {
            return false;
        }
        let expected = self.packet();
        let network_ok = if let Some(ip) = expected.get::<Ipv4>() {
            sent.get::<Ipv4>().is_some_and(|actual| {
                actual.destination == ip.destination
                    && actual.ttl == ip.ttl
                    && actual.dont_fragment == ip.dont_fragment
                    && actual.identification == ip.identification
                    && actual.dscp_ecn == ip.dscp_ecn
                    && actual.reserved_flag == ip.reserved_flag
                    && actual.more_fragments == ip.more_fragments
                    && actual.fragment_offset == ip.fragment_offset
                    && actual.options == ip.options
            })
        } else {
            let ip = expected.get::<Ipv6>().expect("IPv6 authored packet");
            sent.get::<Ipv6>().is_some_and(|actual| {
                actual.destination == ip.destination
                    && actual.hop_limit == ip.hop_limit
                    && actual.flow_label == ip.flow_label
                    && actual.traffic_class == ip.traffic_class
            })
        };
        network_ok
            && if let Some(tcp) = expected.get::<Tcp>() {
                sent.get::<Tcp>().is_some_and(|actual| {
                    actual.source_port == tcp.source_port
                        && actual.destination_port == tcp.destination_port
                        && actual.sequence == tcp.sequence
                        && actual.acknowledgment == tcp.acknowledgment
                        && actual.flags == tcp.flags
                        && actual.window == tcp.window
                        && actual.options == tcp.options
                        && actual.reserved_bits == tcp.reserved_bits
                        && actual.urgent_pointer == tcp.urgent_pointer
                })
            } else if let Some(icmp) = expected.get::<Icmpv4>() {
                sent.get::<Icmpv4>().is_some_and(|actual| {
                    actual.icmp_type == icmp.icmp_type
                        && actual.code == icmp.code
                        && actual.body == icmp.body
                })
            } else {
                let icmp = expected.get::<Icmpv6>().expect("IPv6 echo");
                sent.get::<Icmpv6>().is_some_and(|actual| {
                    actual.icmp_type == icmp.icmp_type
                        && actual.code == icmp.code
                        && actual.body == icmp.body
                })
            }
    }
}
