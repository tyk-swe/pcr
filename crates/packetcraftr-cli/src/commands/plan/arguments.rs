// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{RouteArgs, RoutePolicyArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Route planning is passive: it performs no packet transmission.

Example:
  packetcraftr plan --packet 'ipv4(dst=192.0.2.53)/udp(dport=53)'"#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) route: RouteArgs,
    #[command(flatten)]
    pub(crate) policy: RoutePolicyArgs,
}
