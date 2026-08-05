// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Clap argument and command models.
//!
//! Each command module owns its arguments, command-specific value enums,
//! conversions, help text, and parser tests. This root exposes those models to
//! command execution while the shared modules hold only genuinely reused
//! policy, capture, recipe, route, and offline-limit groups.

pub(super) use build::BuildArgs;
pub(super) use capture::CaptureArgs;
pub(super) use dissect::DissectArgs;
pub(super) use dns::DnsArgs;
pub(super) use exchange::ExchangeArgs;
pub(super) use expert::{CliExpertSeverity, ExpertArgs};
pub(super) use follow::{CliFollowDirection, FollowArgs};
pub(super) use fuzz::FuzzArgs;
pub(super) use offline_limits::{OfflineAnalysisLimits, OfflineCaptureLimits};
pub(super) use plan::PlanArgs;
pub(super) use protocols::ProtocolsArgs;
pub(super) use read::ReadArgs;
pub(super) use recipe::RecipeArgs;
pub(super) use replay::{CliReplayTiming, ReplayArgs};
pub(super) use root::{Cli, CliColorChoice, Command};
pub(super) use route::RouteArgs;
pub(super) use scan::ScanArgs;
pub(super) use send::SendArgs;
pub(super) use stats::{CliStatsTable, StatsArgs};
pub(super) use traceroute::TracerouteArgs;

mod address_family;
mod build;
mod capture;
mod capture_limits;
mod dissect;
mod dns;
mod exchange;
mod expert;
mod follow;
mod fuzz;
mod offline_limits;
mod passive;
mod plan;
mod policy;
mod protocols;
mod read;
mod recipe;
mod replay;
mod root;
mod route;
mod scan;
mod send;
mod stats;
mod traceroute;
