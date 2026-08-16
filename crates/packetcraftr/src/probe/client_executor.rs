// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{Packet, template::Template as PacketTemplate};

/// Shared client and exchange options for live workflow executors.
pub struct ExchangeExecutor<'a, R, N, I> {
    pub(crate) client: &'a crate::Client<R, N, I>,
    pub(crate) options: crate::exchange::Options,
}

impl<'a, R, N, I> ExchangeExecutor<'a, R, N, I> {
    pub fn new(client: &'a crate::Client<R, N, I>, options: crate::exchange::Options) -> Self {
        Self { client, options }
    }
}

impl<R, N, I> ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: packetcraftr_netio::transmit::Sender + packetcraftr_netio::capture::Provider,
{
    pub(crate) fn exchange_for_workflow(
        &self,
        template: &PacketTemplate,
        timeout: std::time::Duration,
        max_template_packets: usize,
        destination: std::net::IpAddr,
        mut matches_request: impl FnMut(
            usize,
            &Packet,
            &packetcraftr_core::decode::DecodedPacket,
        ) -> bool,
    ) -> Result<crate::exchange::Result, crate::BoundaryError> {
        let mut options = self.options.clone();
        options.timeout = timeout;
        options.max_template_packets = max_template_packets;
        options.send.destination = Some(destination);
        self.client
            .exchange_internal(template, options, Some(&mut matches_request))
            .map_err(crate::BoundaryError::from_error)
    }
}
