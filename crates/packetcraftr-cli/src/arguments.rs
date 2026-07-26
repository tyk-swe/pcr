// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Clap argument and command models.

pub(super) use generate::{CliShell, GenerateArgs, GenerateTarget};
pub(super) use network::{
    CaptureArgs, CliLinkMode, CliReplayTiming, ExchangeArgs, ReplayArgs, RouteArgs, SendArgs,
};
pub(super) use offline::{
    BuildArgs, CaptureStreamLimitArgs, CliBuildMode, DecodeArgs, DissectArgs, ProtocolsArgs,
    ReadArgs, RecipeArgs,
};
pub(super) use policy::TrafficPolicyArgs;
pub(super) use root::{Cli, CliColorChoice, Command};
pub(super) use workflow::{DnsArgs, FuzzArgs, ScanArgs, TracerouteArgs};

#[cfg(test)]
pub(super) use workflow::{
    CliAddressFamily, CliDnsQueryType, CliScanTransport, CliTracerouteStrategy,
};

mod capture_limits;
mod generate;
mod network;
mod offline;
mod policy;
mod root;
mod sink;
mod workflow;
