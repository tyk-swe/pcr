// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Instant;

use packetcraftr_core::budget::{Cancellation, Deadline};
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
    /// Passive dry planning: route/source/interface lookup only. The route
    /// lookup receives `deadline`.
    pub fn plan(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &Options,
        deadline: &Deadline,
    ) -> Result<Plan, Error> {
        self.authorize_and_plan(packet, destination, options, &self.routes, deadline, || {
            Ok(())
        })
    }

    /// Plans for an operation bounded by the wall-clock `deadline`, or by
    /// [`PASSIVE_LOOKUP_TIMEOUT`](crate::deadline::PASSIVE_LOOKUP_TIMEOUT)
    /// when it has none. The lookup honors `cancellation`.
    pub(crate) fn plan_with_provider<P: packetcraftr_netio::route::Provider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &Options,
        provider: &P,
        deadline: Option<Instant>,
        cancellation: Option<Cancellation>,
    ) -> Result<Plan, Error> {
        let lookup = match deadline {
            Some(deadline) => crate::deadline::until(deadline, cancellation),
            None => Deadline::new(crate::deadline::PASSIVE_LOOKUP_TIMEOUT)
                .with_cancellation(cancellation),
        };
        self.authorize_and_plan(packet, destination, options, provider, &lookup, || {
            deadline.map_or(Ok(()), ensure_preparation_deadline)
        })
    }

    /// Authorizes, plans through `provider` under `deadline`, and authorizes
    /// the plan. `before_lookup` runs after the declared destinations are
    /// authorized and before the provider is asked.
    fn authorize_and_plan<P: packetcraftr_netio::route::Provider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &Options,
        provider: &P,
        deadline: &Deadline,
        before_lookup: impl FnOnce() -> Result<(), Error>,
    ) -> Result<Plan, Error> {
        self.policy.validate()?;
        if let Some(destination) = destination {
            self.policy.authorize_destination(destination)?;
        }
        // Authorize every declared outer and SRH destination before the route
        // provider can observe one. The completed plan is checked again below
        // so provider-derived selections cannot bypass policy either.
        self.policy.authorize_packet_destinations(packet)?;
        before_lookup()?;
        let plan = plan_route(packet, destination, options, provider, deadline)?;
        self.policy.authorize_packet_sources(packet, &plan)?;
        for destination in &plan.visited_destinations {
            self.policy.authorize_destination(*destination)?;
        }
        Ok(plan)
    }
}
