// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Windows route and interface adapter backed by IP Helper. `GetBestRoute2`
//! supplies route/source selection and `GetAdaptersAddresses` supplies the
//! portable interface snapshot. Neither API emits neighbor traffic.

mod adapter;
mod enumeration;
mod query;

use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;

use crate::{
    interface::{self, Id as InterfaceId},
    route::{self, Decision},
};

// IP Helper calls are synchronous and take no timeout, so every one runs on
// the worker pool and the caller waits only until its deadline.

pub(in crate::platform) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
    deadline: &Deadline,
) -> Result<Decision, route::Error> {
    let interface_hint = interface_hint.cloned();
    super::on_worker(
        deadline,
        "selecting the Windows best route",
        move |deadline| {
            query::route(
                destination,
                interface_hint.as_ref(),
                preferred_source,
                deadline,
            )
        },
    )
}

pub(in crate::platform) fn interface_route(
    requested: &InterfaceId,
    deadline: &Deadline,
) -> Result<Decision, route::Error> {
    let requested = requested.clone();
    super::on_worker(deadline, "selecting a Windows interface", move |_| {
        query::interface_route(&requested)
    })
}

/// One `GetAdaptersAddresses` snapshot.
pub(in crate::platform) fn interfaces(
    deadline: &Deadline,
) -> Result<Vec<interface::Info>, interface::Error> {
    super::on_worker(deadline, "enumerating Windows interfaces", |_| {
        enumeration::interfaces()
    })
    .map_err(interface::Error::native)
}
