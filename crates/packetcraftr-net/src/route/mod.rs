// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

pub(crate) mod intent;
pub(crate) mod materialize;
pub(crate) mod models;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) mod native_policy;
pub(crate) mod planner;
mod provider;
#[cfg(test)]
mod tests;

pub use materialize::MaterializedRoute as Materialized;
pub use models::{
    DestinationScope as Scope, PlanOptions as Options, PlannedRoute as Plan,
    RouteDecision as Decision, RouteProvider as Provider, RouteSelectionReason as SelectionReason,
};
pub use planner::{PlanError as Error, RoutePlanner as Planner};
pub use provider::{NativeRouteError as SystemError, SystemRouteProvider as SystemProvider};

#[doc(hidden)]
pub use materialize::{MaterializedRoute, NeighborError, NeighborResolver};
#[doc(hidden)]
pub use models::{
    DestinationScope, InterfaceId, NeighborRequest, NeighborResolution, NeighborVlanKind,
    NeighborVlanTag, PlanOptions, PlannedRoute, RouteDecision, RouteProvider, RouteSelectionReason,
};
#[doc(hidden)]
pub use planner::{PlanError, RoutePlanner};
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
    NativeRouteSnapshot, finish_route, interface_decision, validate_preferred_source_family,
};

#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
))]
pub(crate) use crate::platform::validate_native_interface;
