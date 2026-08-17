// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;

use super::{BuildMode, RouteArgs, SendPolicyArgs};

#[derive(Debug, Args)]
pub(crate) struct SendArgs {
    #[command(flatten)]
    pub(crate) route: RouteArgs,
    /// Strict or permissive packet construction.
    #[arg(long, value_enum, default_value_t = BuildMode::Strict)]
    pub(crate) mode: BuildMode,
    /// Per-operation opt-in required for a permissively built live frame.
    #[arg(long)]
    pub(crate) allow_permissive_live: bool,
    #[command(flatten)]
    pub(crate) policy: SendPolicyArgs,
}
