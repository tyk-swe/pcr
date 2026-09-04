// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared Clap groups; command-specific options stay in `commands/<command>/arguments.rs`.

pub(crate) use address_family::AddressFamily;
pub(crate) use capture_limits::CaptureLimitsArgs;
pub(crate) use offline_limits::{
    CaptureReaderBoundsArgs, OfflineCaptureLimitsArgs, OfflineLimitsArgs,
};
pub(crate) use packet_budget::PacketBudgetArgs;
pub(crate) use policy::{
    Captured, FuzzPolicyArgs, HostnamePolicyArgs, ReplayPolicyArgs, RoutePolicyArgs,
    SendPolicyArgs, TrafficBudgetArgs,
};
pub(crate) use recipe::{BuildMode, RecipeArgs};
pub(crate) use route::{LinkMode, RouteArgs, RouteSelectionArgs};
pub(crate) use send::SendArgs;
pub(crate) use tls_ports::TlsPortArgs;

mod address_family;
mod capture_limits;
mod offline_limits;
mod packet_budget;
mod policy;
mod recipe;
mod route;
mod send;
mod tls_ports;
