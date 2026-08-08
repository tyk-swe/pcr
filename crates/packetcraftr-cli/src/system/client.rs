// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::{
    live::{self as client, Client},
    network as net, packet,
    packet::protocol,
};

use super::super::errors::CliError;

pub(crate) type SystemPacketIo =
    net::transmit::Dispatch<net::transmit::SystemLayer2, net::transmit::SystemLayer3>;
pub(crate) type SystemExchangeIo = (SystemPacketIo, net::capture::SystemProvider);
pub(crate) type SystemClient =
    Client<net::route::SystemProvider, net::neighbor::SystemResolver, SystemExchangeIo>;

pub(crate) fn default_registry_arc() -> Result<Arc<packet::registry::Registry>, CliError> {
    protocol::builtin::registry()
        .map(Arc::new)
        .map_err(|source| {
            CliError::new(70, format!("built-in registry invariant failed: {source}"))
        })
}

pub(crate) fn system_client(
    registry: Arc<packet::registry::Registry>,
    policy: client::policy::Policy,
) -> SystemClient {
    Client::new(
        registry,
        net::route::SystemProvider,
        net::neighbor::SystemResolver::default(),
        (
            net::transmit::Dispatch::new(net::transmit::SystemLayer2, net::transmit::SystemLayer3),
            net::capture::SystemProvider,
        ),
        policy,
    )
}
