// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Cow;
use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::packet::Packet;
use packetcraftr_netio::Error as LiveIoError;

use crate::Client;
use crate::Error;
use crate::clock::Clock;
use crate::providers::Providers;
use crate::route::{Options, Plan, plan as plan_route};

/// Whether `deadline` has arrived.
///
/// The boundary itself is expired: no time remains once nothing is left, as
/// [`packetcraftr_netio::deadline::remaining`] reports. Correlation
/// eligibility is a separate test on the capture timestamp and still accepts
/// a frame received at the window's end.
#[must_use]
pub(crate) fn expired(deadline: &Deadline) -> bool {
    !matches!(deadline.remaining(), Ok(remaining) if !remaining.is_zero())
}

/// Refuses to continue preparing once `deadline` has arrived. Preparation
/// callers retain the error vocabulary of their operation.
pub(crate) fn ensure_preparation_deadline(deadline: &Deadline) -> Result<(), Error> {
    if expired(deadline) {
        return Err(LiveIoError::DeadlineExceeded {
            operation: "preparing the exchange",
        }
        .into());
    }
    Ok(())
}

impl<P: Providers, K: Clock> Client<P, K> {
    /// Passive dry planning: route, source, and interface lookup only.
    ///
    /// The declared destinations are authorized first; an interface selector
    /// is resolved through the interface provider only after that, and the
    /// route lookup receives `deadline`.
    ///
    /// # Errors
    ///
    /// Returns the policy denial, the interface or route lookup failure, or
    /// the planning refusal.
    pub fn plan(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &Options,
        deadline: &Deadline,
    ) -> Result<Plan, Error> {
        self.authorize_and_plan(
            packet,
            destination,
            options,
            self.providers.route(),
            deadline,
            || Ok(()),
        )
    }

    /// Authorizes, resolves the interface selector, plans through `routes`
    /// under `deadline`, and authorizes the plan. `before_lookup` runs after
    /// the declared destinations are authorized and before any provider is
    /// asked.
    pub(crate) fn authorize_and_plan<R: packetcraftr_netio::route::Provider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &Options,
        routes: &R,
        deadline: &Deadline,
        before_lookup: impl FnOnce() -> Result<(), Error>,
    ) -> Result<Plan, Error> {
        self.policy.validate()?;
        if let Some(destination) = destination {
            self.policy.authorize_destination(destination)?;
        }
        // Authorize every declared outer and SRH destination before a
        // provider can observe one. The completed plan is checked again below
        // so provider-derived selections cannot bypass policy either.
        self.policy.authorize_packet_destinations(packet)?;
        before_lookup()?;
        let options = self.resolve_interface(options, deadline)?;
        let plan = plan_route(packet, destination, &options, routes, deadline)?;
        self.policy.authorize_packet_sources(packet, &plan)?;
        for destination in &plan.visited_destinations {
            self.policy.authorize_destination(*destination)?;
        }
        Ok(plan)
    }

    /// `options` with its interface selector resolved through the interface
    /// provider. A refused operation never gets here, so it never
    /// enumerates interfaces.
    fn resolve_interface<'o>(
        &self,
        options: &'o Options,
        deadline: &Deadline,
    ) -> Result<Cow<'o, Options>, Error> {
        let Some(selector) = options
            .interface
            .as_ref()
            .filter(|selector| selector.id().is_none())
        else {
            return Ok(Cow::Borrowed(options));
        };
        let id = self
            .interfaces
            .resolve(selector, self.providers.interface(), deadline)?;
        Ok(Cow::Owned(Options {
            interface: Some(id.into()),
            ..options.clone()
        }))
    }
}
