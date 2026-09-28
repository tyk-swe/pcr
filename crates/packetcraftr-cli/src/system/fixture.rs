// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::{CaptureProviders, Client, PacketProviders, ProviderSet};
use packetcraftr_core as core;
use packetcraftr_netio as net;

pub(crate) fn capturing<C: net::capture::Provider + 'static>(
    registry: Arc<core::registry::Registry>,
    policy: packetcraftr::policy::Policy,
    capture: C,
) -> Client<impl CaptureProviders> {
    Client::new(
        registry,
        policy,
        ProviderSet::capture(net::interface::SystemProvider, capture),
    )
}

pub(crate) fn transmitting<R, N, T>(
    registry: Arc<core::registry::Registry>,
    policy: packetcraftr::policy::Policy,
    route: R,
    interface: N,
    transmit: T,
) -> Client<impl PacketProviders>
where
    R: net::route::Provider + 'static,
    N: net::interface::Provider + 'static,
    T: net::transmit::Provider + 'static,
{
    Client::new(
        registry,
        policy,
        ProviderSet::packet(route, interface, net::capture::SystemProvider, transmit),
    )
}
