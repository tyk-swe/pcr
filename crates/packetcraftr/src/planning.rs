// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Instant;

use packetcraftr_core::packet::Packet;
use packetcraftr_netio::deadline::remaining_before;
use packetcraftr_netio::{Error as LiveIoError, transmit::Provider as PacketIo};

use crate::Client;
use crate::Error;
use crate::route::{Options, Plan, plan as plan_route};

/// Whether `deadline` has arrived.
///
/// The boundary instant itself is expired: no time remains once
/// `now == deadline`, as [`remaining_before`] reports. Correlation eligibility
/// is a separate test on the capture timestamp and still accepts a frame whose
/// `received_at <= deadline`.
///
/// Preparation callers retain the error vocabulary of their operation.
#[must_use]
pub(crate) fn expired(deadline: Instant) -> bool {
    remaining_before(deadline).is_none()
}

pub(crate) fn ensure_preparation_deadline(deadline: Instant) -> Result<(), Error> {
    if expired(deadline) {
        return Err(LiveIoError::DeadlineExceeded {
            operation: "preparing the exchange",
        }
        .into());
    }
    Ok(())
}

impl<R, I> Client<R, I>
where
    R: packetcraftr_netio::route::Provider,
    I: PacketIo,
{
    /// Passive dry planning: route/source/interface lookup only.
    pub fn plan(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &Options,
    ) -> Result<Plan, Error> {
        self.plan_with_provider(packet, destination, options, &self.routes, None)
    }

    pub(crate) fn plan_with_provider<P: packetcraftr_netio::route::Provider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &Options,
        provider: &P,
        deadline: Option<Instant>,
    ) -> Result<Plan, Error> {
        self.policy.validate()?;
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
