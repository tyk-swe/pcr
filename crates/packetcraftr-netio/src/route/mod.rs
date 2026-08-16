// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

mod error;
mod intent;
pub(crate) mod materialize;
mod models;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod native_policy;
mod planner;
mod provider;

pub use error::PlanError as Error;
pub use materialize::{MaterializedRoute as Materialized, materialize};
pub use models::{
    DestinationScope as Scope, PlanOptions as Options, PlannedRoute as Plan,
    RouteDecision as Decision, RouteProvider as Provider, RouteSelectionReason as SelectionReason,
};
pub use planner::plan;
pub use provider::{NativeRouteError as SystemError, SystemRouteProvider as SystemProvider};

pub(crate) use materialize::MaterializedRoute;
pub(crate) use models::{DestinationScope, PlannedRoute, RouteDecision, RouteSelectionReason};
pub(crate) use provider::NativeRouteError;

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
