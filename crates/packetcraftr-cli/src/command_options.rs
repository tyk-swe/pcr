// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared Clap groups; command-specific options stay in `commands/<command>/arguments.rs`.

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
