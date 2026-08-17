// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Instant;

use packetcraftr_core::{Packet, semantics::BuiltinProtocol};
use packetcraftr_netio::{
    Error as LiveIoError,
    neighbor::Resolver as NeighborResolver,
    route::{
        Options as PlanOptions, Plan as PlannedRoute, Provider as RouteProvider, plan as plan_route,
    },
    transmit::Sender as PacketIo,
};

use crate::Client;
use crate::Error;
use crate::target::{Authorized, Error as TargetError, Family, Resolver, Target};

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
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo,
{
    /// planning. A denied hostname never reaches `resolver`; if any resolved
    /// address is denied, no route-provider method is called.
    pub fn plan_target<H: Resolver>(
        &self,
        packet: &Packet,
        target: &Target,
        resolver: &H,
        options: &PlanOptions,
    ) -> Result<(Authorized, PlannedRoute), Error> {
        let resolved = self.policy.resolve_target(target, resolver)?;
        let packet_ip_version = packet
            .iter()
            .find_map(|layer| match BuiltinProtocol::of(layer) {
                Some(BuiltinProtocol::Ipv4) => Some(Family::Ipv4),
                Some(BuiltinProtocol::Ipv6) => Some(Family::Ipv6),
                _ => None,
            });
        let selected = match packet_ip_version {
            Some(version) => resolved.address_for_family(version).ok_or(
                TargetError::AddressFamilyUnavailable {
                    family: version.label(),
                },
            )?,
            None => resolved.selected_address(),
        };
        let plan = self.plan(packet, Some(selected), options)?;
        Ok((resolved, plan))
    }

    /// Passive dry planning: route/source/interface lookup only.
    pub fn plan(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &PlanOptions,
    ) -> Result<PlannedRoute, Error> {
        self.plan_with_provider(packet, destination, options, &self.routes, None)
    }

    pub(crate) fn plan_with_provider<P: RouteProvider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &PlanOptions,
        provider: &P,
        deadline: Option<Instant>,
    ) -> Result<PlannedRoute, Error> {
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
        for destination in &plan.visited_destinations {
            self.policy.authorize_destination(*destination)?;
        }
        Ok(plan)
    }
}
