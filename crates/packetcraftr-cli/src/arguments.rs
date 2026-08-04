// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Clap argument and command models.

pub(super) use build::{BuildArgs, RecipeArgs};
pub(super) use capture::CaptureArgs;
pub(super) use dissect::DissectArgs;
pub(super) use dns::DnsArgs;
pub(super) use exchange::ExchangeArgs;
pub(super) use expert::ExpertArgs;
pub(super) use follow::{CliFollowDirection, FollowArgs};
pub(super) use fuzz::FuzzArgs;
pub(super) use plan::{PlanArgs, RouteArgs};
pub(super) use protocols::ProtocolsArgs;
pub(super) use read::ReadArgs;
pub(super) use replay::{CliReplayTiming, ReplayArgs};
pub(super) use root::{Cli, CliColorChoice, Command};
pub(super) use scan::ScanArgs;
pub(super) use send::SendArgs;
pub(super) use stats::{CliStatsTable, OfflineAnalysisLimits, OfflineCaptureLimits, StatsArgs};
pub(super) use traceroute::TracerouteArgs;

mod build;
mod capture;
mod capture_limits;
mod dissect;
mod dns;
mod exchange;
mod expert;
mod follow;
mod fuzz;
mod network;
mod offline;
mod plan;
mod policy;
mod protocols;
mod read;
mod replay;
mod root;
mod scan;
mod send;
mod stats;
mod traceroute;
mod workflow;
