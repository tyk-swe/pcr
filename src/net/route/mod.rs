// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

mod models;
mod planner;
mod provider;
#[cfg(test)]
mod tests;

pub use models::{
    DestinationScope, InterfaceId, LinkCapability, LinkMode, MacAddress, NeighborRequest,
    NeighborResolution, NeighborVlanKind, NeighborVlanTag, PlanOptions, PlannedRoute,
    RouteDecision, RouteProvider, RouteSelectionReason,
};
pub use planner::{MaterializedRoute, NeighborError, NeighborResolver, PlanError, RoutePlanner};
pub use provider::{NativeRouteError, SystemRouteProvider};

pub(crate) use models::MAX_NEIGHBOR_VLAN_TAGS;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(super) use planner::classify_destination;
