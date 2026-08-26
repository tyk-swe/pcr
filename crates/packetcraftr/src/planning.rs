// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Instant;

use packetcraftr_core::Packet;
use packetcraftr_netio::{
    Error as LiveIoError, route::plan as plan_route, transmit::Sender as PacketIo,
};

use crate::Client;
use crate::Error;

pub(crate) fn ensure_preparation_deadline(deadline: Instant) -> Result<(), Error> {
    if deadline.checked_duration_since(Instant::now()).is_none() {
        return Err(LiveIoError::DeadlineExceeded {
            operation: "preparing the exchange",
        }
        .into());
    }
    Ok(())
}

impl<R, N, I> Client<R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo,
{
    /// Passive dry planning: route/source/interface lookup only.
    pub fn plan(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &packetcraftr_netio::route::Options,
    ) -> Result<packetcraftr_netio::route::Plan, Error> {
        self.plan_with_provider(packet, destination, options, &self.routes, None)
    }

    pub(crate) fn plan_with_provider<P: packetcraftr_netio::route::Provider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &packetcraftr_netio::route::Options,
        provider: &P,
        deadline: Option<Instant>,
    ) -> Result<packetcraftr_netio::route::Plan, Error> {
        if let Some(destination) = destination {
            self.policy.authorize_destination(destination)?;
        }
        // Authorize every declared outer and SRH destination before the route
        // provider can observe one. The completed plan is checked again below
        // so provider-derived selections cannot bypass policy either.
        self.policy.authorize_packet_destinations(packet)?;
        if let Some(deadline) = deadline {
            ensure_preparation_deadline(deadline)?;
        }
        let plan = plan_route(packet, destination, options, provider)?;
        self.policy.authorize_packet_sources(packet, &plan)?;
        for destination in &plan.visited_destinations {
            self.policy.authorize_destination(*destination)?;
        }
        Ok(plan)
    }
}
