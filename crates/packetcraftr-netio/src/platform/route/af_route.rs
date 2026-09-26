// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Passive macOS route lookup backed by routing sockets and the interface
//! backend's `getifaddrs(3)` snapshot. It performs no neighbor discovery,
//! capture, or transmission.

mod query;

use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;

use crate::{
    interface::Id as InterfaceId,
    route::{self, Decision},
};

pub(in crate::platform) use query::interface_route;

/// A routing-socket query waits on the kernel, so it runs on the worker pool.
pub(in crate::platform) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
    deadline: &Deadline,
) -> Result<Decision, route::Error> {
    let interface_hint = interface_hint.cloned();
    crate::platform::common::on_worker(
        deadline,
        "querying the macOS routing socket",
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
