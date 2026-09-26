// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Linux route lookup backed by route netlink.

use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;

use self::query::query_route;
use super::find_interface;
use crate::platform::{common::netlink::with_netlink, interface::netlink::snapshot};
use crate::{
    interface::Id as InterfaceId,
    route::{self, Decision, normalize::interface_decision},
};

mod query;

pub(in crate::platform) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
    deadline: &Deadline,
) -> Result<Decision, route::Error> {
    let interface_hint = interface_hint.cloned();
    with_netlink(deadline, move |handle| {
        query_route(handle, destination, interface_hint, preferred_source)
    })
}

pub(in crate::platform) fn interface_route(
    requested: &InterfaceId,
    deadline: &Deadline,
) -> Result<Decision, route::Error> {
    interface_decision(find_interface(&snapshot(deadline)?, requested)?)
}
