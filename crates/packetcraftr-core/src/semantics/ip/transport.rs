// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! All-or-nothing transport tuple interpretation.

use super::path::{DESTINATION_PORT, SOURCE_PORT};
use crate::semantics::{BuiltinProtocol, Layer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportKey {
    pub protocol: BuiltinProtocol,
    pub source_port: u16,
    pub destination_port: u16,
}

/// Extracts an all-or-nothing transport tuple. Missing, wrongly typed, and
/// out-of-range ports never become a partially comparable key.
pub fn transport_key(layer: &dyn Layer) -> Option<TransportKey> {
    let protocol = BuiltinProtocol::of(layer)?;
    if !matches!(
        protocol,
        BuiltinProtocol::Tcp | BuiltinProtocol::Udp | BuiltinProtocol::Sctp
    ) {
        return None;
    }
    let source_port = u16::try_from(layer.field(SOURCE_PORT)?.as_u64()?).ok()?;
    let destination_port = u16::try_from(layer.field(DESTINATION_PORT)?.as_u64()?).ok()?;
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
