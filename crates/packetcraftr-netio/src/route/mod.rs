// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

mod error;
mod intent;
mod materialize;
mod models;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod native_policy;
mod planner;
mod provider;

pub use error::Error;
pub use materialize::{Materialized, materialize};
pub use models::{Decision, Options, Plan, Provider, Scope, SelectionReason};
pub use planner::plan;
pub use provider::{SystemError, SystemProvider};

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
