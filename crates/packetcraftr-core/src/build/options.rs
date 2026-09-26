// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::codec::Mode;
use crate::diagnostic::Diagnostic;
use crate::layer::{Malformed, Padding};
use crate::layout::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE, PacketLayout};
use crate::packet::Packet;
use crate::protocol::BuiltinProtocol;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub mode: Mode,
    pub max_layers: usize,
    pub max_packet_size: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            mode: Mode::Strict,
            max_layers: DEFAULT_MAX_LAYERS,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
        }
    }
}

/// Exact encoded bytes plus the resolved packet, byte layout, and diagnostics.
#[derive(Clone, Debug)]
pub struct BuiltPacket {
    pub bytes: Bytes,
    pub packet: Packet,
    pub layout: PacketLayout,
    pub diagnostics: Vec<Diagnostic>,
    /// The codec mode the packet was built with.
    pub mode: Mode,
}

impl BuiltPacket {
    /// Whether any layer of the built packet is a [`Malformed`] layer.
    #[must_use]
    pub fn contains_malformed(&self) -> bool {
        self.packet
            .iter()
            .any(<dyn crate::layer::Layer>::is::<Malformed>)
    }

    /// Whether the packet carries padding trailing an IPv4, IPv6, UDP, or
    /// PPPoE payload, bytes a network stack may treat as part of the datagram.
    #[must_use]
    pub fn contains_network_trailer(&self) -> bool {
        self.packet.iter().any(|layer| {
            layer
                .downcast_ref::<Padding>()
                .and_then(|padding| padding.outside_layer)
                .and_then(|outside_layer| self.packet.layer(outside_layer))
                .is_some_and(|outside| {
                    matches!(
                        BuiltinProtocol::of(outside),
                        Some(
                            BuiltinProtocol::Ipv4
                                | BuiltinProtocol::Ipv6
                                | BuiltinProtocol::Udp
                                | BuiltinProtocol::Pppoe
                        )
                    )
                })
        })
    }
}
