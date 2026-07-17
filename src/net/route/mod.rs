// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

pub(crate) mod models;
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

pub(crate) use models::{
    DestinationScope, InterfaceId, NeighborRequest, NeighborResolution, NeighborVlanKind,
    NeighborVlanTag, PlanOptions, PlannedRoute, RouteDecision, RouteProvider, RouteSelectionReason,
};
pub(crate) use planner::{
    MaterializedRoute, NeighborError, NeighborResolver, PlanError, RoutePlanner,
};
pub(crate) use provider::{NativeRouteError, SystemRouteProvider};

pub(crate) use models::MAX_NEIGHBOR_VLAN_TAGS;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(super) use planner::classify_destination;
