// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

mod error;
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

pub use error::PlanError as Error;
pub use materialize::{MaterializedRoute as Materialized, materialize};
pub use models::{
    DestinationScope as Scope, PlanOptions as Options, PlannedRoute as Plan,
    RouteDecision as Decision, RouteProvider as Provider, RouteSelectionReason as SelectionReason,
};
pub use planner::plan;
pub use provider::{NativeRouteError as SystemError, SystemRouteProvider as SystemProvider};

pub(crate) use materialize::{MaterializedRoute, NeighborError, NeighborResolver};
pub(crate) use models::{DestinationScope, PlannedRoute, RouteDecision, RouteSelectionReason};
pub(crate) use provider::NativeRouteError;

pub(crate) use crate::interface::Id as InterfaceId;
pub(crate) use crate::neighbor::{
    MAX_VLAN_TAGS as MAX_NEIGHBOR_VLAN_TAGS, Request as NeighborRequest,
    Resolution as NeighborResolution, VlanKind as NeighborVlanKind, VlanTag as NeighborVlanTag,
};
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
