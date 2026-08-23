// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared Clap groups; command-specific options stay in `commands/<command>/arguments.rs`.

mod address_family;
mod capture_limits;
mod offline_limits;
mod policy;
mod recipe;
mod route;
mod send;

pub(crate) use address_family::AddressFamily;
pub(crate) use capture_limits::CaptureLimitsArgs;
pub(crate) use offline_limits::{OfflineCaptureLimitsArgs, OfflineLimitsArgs};
pub(crate) use policy::{
    HostnamePolicyArgs, HostnameResolutionArgs, PermissivePacketArgs, PublicDestinationArgs,
    SendPolicyArgs, SourceSpoofingArgs, TrafficBudgetArgs,
};
pub(crate) use recipe::{BuildMode, RecipeArgs};
pub(crate) use route::{LinkMode, RouteArgs, RouteSelectionArgs};
pub(crate) use send::SendArgs;
