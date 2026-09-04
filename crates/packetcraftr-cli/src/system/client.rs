// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::{Client as WorkflowClient, core, netio as net};

type SystemSender =
    net::transmit::ModeSender<net::transmit::SystemLayer2, net::transmit::SystemLayer3>;
type ExchangeIo = net::PacketIo<SystemSender, net::capture::SystemProvider>;
pub(crate) type Client =
    WorkflowClient<net::route::SystemProvider, net::neighbor::SystemResolver, ExchangeIo>;
pub(crate) type Exchange<'a> = packetcraftr::probe::ExchangeExecutor<
    'a,
    net::route::SystemProvider,
    net::neighbor::SystemResolver,
    ExchangeIo,
>;

pub(crate) fn client(
    registry: Arc<core::registry::Registry>,
    policy: packetcraftr::policy::Policy,
) -> Client {
    WorkflowClient::new(
        registry,
        net::route::SystemProvider,
        net::neighbor::SystemResolver::default(),
        net::PacketIo::new(
            net::transmit::ModeSender::new(
                net::transmit::SystemLayer2,
                net::transmit::SystemLayer3,
            ),
            net::capture::SystemProvider,
        ),
        policy,
    )
}
