// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Clap argument and command models.

pub(super) use network::{
    CaptureArgs, CliReplayTiming, ExchangeArgs, ReplayArgs, RouteArgs, SendArgs,
};
pub(super) use offline::{
    BuildArgs, CliFollowDirection, CliStatsTable, DissectArgs, ExpertArgs, FollowArgs,
    OfflineAnalysisLimits, OfflineCaptureLimits, ProtocolsArgs, ReadArgs, RecipeArgs, StatsArgs,
};
pub(super) use root::{Cli, CliColorChoice, Command};
pub(super) use workflow::{DnsArgs, FuzzArgs, ScanArgs, TracerouteArgs};

mod capture_limits;
mod network;
mod offline;
mod policy;
mod root;
mod workflow;
