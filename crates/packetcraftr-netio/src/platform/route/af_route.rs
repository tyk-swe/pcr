// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Passive macOS route/interface adapter backed by `getifaddrs(3)` and routing sockets.
//! It performs no neighbor discovery, capture, or transmission.

mod enumeration;
mod parser;
mod query;

use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;

use crate::{
    interface::{self, Id as InterfaceId},
    route::{Decision, SystemError},
};

pub(in crate::platform) use query::interface_route;

/// A routing-socket query waits on the kernel, so it runs on the worker pool.
pub(in crate::platform) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
    deadline: &Deadline,
) -> Result<Decision, SystemError> {
    let interface_hint = interface_hint.cloned();
    super::on_worker(
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

/// `getifaddrs(3)` answers without waiting; the interface capability has
/// already checked the caller's deadline.
pub(in crate::platform) fn interfaces(
    _deadline: &Deadline,
) -> Result<Vec<interface::Info>, interface::Error> {
    enumeration::interfaces().map_err(interface::Error::native)
}
