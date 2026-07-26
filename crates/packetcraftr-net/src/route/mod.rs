// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

pub mod models;
pub mod planner;
#[cfg(test)]
mod tests;

pub use models::{
    DestinationScope, InterfaceId, NeighborRequest, NeighborResolution, NeighborVlanKind,
    NeighborVlanTag, PlanOptions, PlannedRoute, RouteDecision, RouteProvider, RouteSelectionReason,
};
pub use models::{
    DestinationScope as Scope, PlanOptions as Options, PlannedRoute as Plan,
    RouteDecision as Decision, RouteProvider as Provider, RouteSelectionReason as SelectionReason,
};
pub use planner::{MaterializedRoute, NeighborError, NeighborResolver, PlanError, RoutePlanner};
pub use planner::{MaterializedRoute as Materialized, PlanError as Error, RoutePlanner as Planner};

pub use models::MAX_NEIGHBOR_VLAN_TAGS;
pub use planner::classify_destination;
