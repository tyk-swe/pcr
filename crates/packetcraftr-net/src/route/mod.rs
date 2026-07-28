// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

pub(crate) mod models;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod native_policy;
pub(crate) mod planner;
mod provider;
#[cfg(test)]
mod tests;

pub use models::{
    DestinationScope as Scope, PlanOptions as Options, PlannedRoute as Plan,
    RouteDecision as Decision, RouteProvider as Provider, RouteSelectionReason as SelectionReason,
};
pub use planner::{MaterializedRoute as Materialized, PlanError as Error, RoutePlanner as Planner};
pub use provider::{NativeRouteError as SystemError, SystemRouteProvider as SystemProvider};

#[doc(hidden)]
pub use models::{
    DestinationScope, InterfaceId, NeighborRequest, NeighborResolution, NeighborVlanKind,
    NeighborVlanTag, PlanOptions, PlannedRoute, RouteDecision, RouteProvider, RouteSelectionReason,
};
#[doc(hidden)]
pub use planner::{MaterializedRoute, NeighborError, NeighborResolver, PlanError, RoutePlanner};
#[doc(hidden)]
pub use provider::{NativeRouteError, SystemRouteProvider};

pub(crate) use models::MAX_NEIGHBOR_VLAN_TAGS;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) use native_policy::find_interface;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) use native_policy::{
    NativeRouteSnapshot, finish_route, interface_decision, validate_native_interface,
    validate_preferred_source_family,
};
