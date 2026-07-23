// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Clap argument and command models.

mod capture_limits;
mod network;
mod offline;
mod policy;
mod root;
mod workflow;

pub(super) use network::{
    CaptureArgs, CliReplayTiming, ExchangeArgs, ReplayArgs, RouteArgs, SendArgs,
};
pub(super) use offline::{BuildArgs, CliBuildMode, DissectArgs, ReadArgs, RecipeArgs};
pub(super) use root::{Cli, CliColorChoice, Command};
pub(super) use workflow::{DnsArgs, FuzzArgs, ScanArgs, TracerouteArgs};

#[cfg(test)]
pub(super) use network::CliLinkMode;
#[cfg(test)]
pub(super) use workflow::{
    CliAddressFamily, CliDnsQueryType, CliScanTransport, CliTracerouteStrategy,
};
