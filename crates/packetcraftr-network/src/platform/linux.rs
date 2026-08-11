// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Linux route and interface adapter backed by route netlink.

#![forbid(unsafe_code)]

use std::net::IpAddr;

use self::{
    query::{query_interfaces, query_route},
    worker::with_netlink,
};
use super::{find_interface, interface_decision, validate_preferred_source_family};
use crate::{
    interface::InterfaceInfo,
    route::{InterfaceId, NativeRouteError, RouteDecision},
};

mod query;
mod worker;

pub(super) fn interfaces() -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    with_netlink(|handle| async move { query_interfaces(&handle).await })
}

pub(super) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    validate_preferred_source_family(destination, preferred_source)?;
    let interface_hint = interface_hint.cloned();
    with_netlink(move |handle| query_route(handle, destination, interface_hint, preferred_source))
}

pub(super) fn interface_route(requested: &InterfaceId) -> Result<RouteDecision, NativeRouteError> {
    interface_decision(find_interface(&interfaces()?, requested)?)
}

fn os_error(operation: &'static str, error: impl std::fmt::Display) -> NativeRouteError {
    NativeRouteError::OperatingSystem {
        operation,
        message: error.to_string(),
    }
}
