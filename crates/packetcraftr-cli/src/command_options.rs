// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Reusable Clap groups for packet input, routing, authorization, and bounds.
//!
//! Command-specific options stay in `commands/<command>/arguments.rs`. This
//! module contains only groups whose parsing and conversion contract is shared
//! by multiple commands.

pub(crate) use address_family::CliAddressFamily;
pub(crate) use capture_limits::CaptureLimitArgs;
pub(crate) use offline_limits::{OfflineAnalysisLimits, OfflineCaptureLimits};
pub(crate) use policy::{
    FuzzPolicyArgs, HostnameTrafficPolicyArgs, PlanPolicyArgs, ReplayPolicyArgs, SendPolicyArgs,
};
pub(crate) use recipe::{CliBuildMode, RecipeArgs};
pub(crate) use route::{CliLinkMode, RouteArgs};

mod address_family;
mod capture_limits;
mod offline_limits;
mod policy;
mod recipe;
mod route;
