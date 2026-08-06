// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;

use crate::command_options::{CliBuildMode, RouteArgs, SendPolicyArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Live transmission is policy-gated and may require native features, dependencies, and privileges.

Example:
  packetcraftr send --packet 'ipv4(dst=192.0.2.1)/icmpv4(type=8,code=0)'"#;

#[derive(Debug, Args)]
pub(crate) struct SendArgs {
    #[command(flatten)]
    pub(crate) route: RouteArgs,
    /// Strict or permissive packet construction.
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    pub(crate) mode: CliBuildMode,
    /// Per-operation opt-in required for a permissively built live frame.
    #[arg(long)]
    pub(crate) allow_permissive_live: bool,
    #[command(flatten)]
    pub(crate) policy: SendPolicyArgs,
}
