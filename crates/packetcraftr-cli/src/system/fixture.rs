// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Clients for command unit tests: fakes fill the provider slots a test
//! drives, and every other slot is the system provider, which the test never
//! reaches. The clients carry neither the process cancellation signal nor a
//! registered runtime.

use std::sync::Arc;

use packetcraftr::{Client, ProviderSet, Providers};
use packetcraftr_core as core;
use packetcraftr_netio as net;

/// A client capturing through `capture`.
pub(crate) fn capturing<C: net::capture::Provider + 'static>(
    registry: Arc<core::registry::Registry>,
    policy: packetcraftr::policy::Policy,
    capture: C,
) -> Client<impl Providers> {
    Client::new(
        registry,
        policy,
        ProviderSet {
            route: net::route::SystemProvider,
            interface: net::interface::SystemProvider,
            capture,
            transmit: net::transmit::SystemProvider,
            tcp: net::tcp::SystemProvider,
            resolver: packetcraftr::target::SystemResolver,
        },
    )
}

/// A client routing through `route` and `interface` and transmitting
/// through `transmit`.
pub(crate) fn transmitting<R, N, T>(
    registry: Arc<core::registry::Registry>,
    policy: packetcraftr::policy::Policy,
    route: R,
    interface: N,
    transmit: T,
) -> Client<impl Providers>
where
    R: net::route::Provider + 'static,
    N: net::interface::Provider + 'static,
    T: net::transmit::Provider + 'static,
{
    Client::new(
        registry,
        policy,
        ProviderSet {
            route,
            interface,
            capture: net::capture::SystemProvider,
            transmit,
            tcp: net::tcp::SystemProvider,
            resolver: packetcraftr::target::SystemResolver,
        },
    )
}
