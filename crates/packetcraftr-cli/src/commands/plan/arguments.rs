// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;

use crate::command_options::{PlanPolicyArgs, RouteArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Route planning is passive: it performs no packet transmission.

Example:
  packetcraftr plan --packet 'ipv4(dst=192.0.2.53)/udp(dport=53)'"#;

#[derive(Debug, Args)]
pub(crate) struct PlanArgs {
    #[command(flatten)]
    pub(crate) route: RouteArgs,
    #[command(flatten)]
    pub(crate) policy: PlanPolicyArgs,
}
