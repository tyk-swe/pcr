// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::layer::Layer;
use crate::protocol::BuiltinProtocol;
use crate::protocol::transport::{Sctp, Tcp, Udp};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportKey {
    pub protocol: BuiltinProtocol,
    pub source_port: u16,
    pub destination_port: u16,
}

/// Extracts the transport tuple of a built-in TCP, UDP, or SCTP layer. Any
/// other layer, including a custom one that reflects port fields, has none.
pub fn transport_key(layer: &dyn Layer) -> Option<TransportKey> {
    let (protocol, source_port, destination_port) = if let Some(tcp) = layer.downcast_ref::<Tcp>() {
        (BuiltinProtocol::Tcp, tcp.source_port, tcp.destination_port)
    } else if let Some(udp) = layer.downcast_ref::<Udp>() {
        (BuiltinProtocol::Udp, udp.source_port, udp.destination_port)
    } else {
        let sctp = layer.downcast_ref::<Sctp>()?;
        (
            BuiltinProtocol::Sctp,
            sctp.source_port,
            sctp.destination_port,
        )
    };
    Some(TransportKey {
        protocol,
        source_port,
        destination_port,
    })
}

pub fn transport_keys_are_reversed(request: &dyn Layer, response: &dyn Layer) -> bool {
    let (Some(request), Some(response)) = (transport_key(request), transport_key(response)) else {
        return false;
    };
    request.protocol == response.protocol
        && request.source_port == response.destination_port
        && request.destination_port == response.source_port
}
