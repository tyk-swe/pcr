// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{HostnameResolutionArgs, PublicDestinationArgs, RouteArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Route planning is passive: it performs no packet transmission.

Example:
  packetcraftr plan --packet 'ipv4(dst=192.0.2.53)/udp(dport=53)'"#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) route: RouteArgs,
    #[command(flatten)]
    pub(crate) policy: PolicyArgs,
}

#[derive(Clone, Debug, clap::Args)]
pub(crate) struct PolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    hostname_resolution: HostnameResolutionArgs,
}

impl PolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        policy
    }
}
