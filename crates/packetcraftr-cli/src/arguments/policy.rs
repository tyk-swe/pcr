// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Shared live-traffic and replay policy arguments.

use std::path::PathBuf;

use clap::Args;
use packetcraftr::{capture, client};

use super::super::errors::CliError;
use super::super::input::read_policy_file;

#[derive(Clone, Debug, Args)]
pub(crate) struct TrafficPolicyArgs {
    /// Read policy defaults from a JSON or YAML file; flags override it.
    #[arg(long, value_name = "PATH")]
    pub(crate) policy_file: Option<PathBuf>,
    /// Deliberately authorize globally routable destinations.
    #[arg(long)]
    allow_public_destinations: bool,
    /// Deliberately authorize hostname resolution before route lookup.
    #[arg(long)]
    allow_hostname_resolution: bool,
    /// Policy-level opt-in for permissively built live packets.
    #[arg(long)]
    allow_permissive_packets: bool,
    /// Maximum packets authorized for one operation [default: 10000].
    #[arg(long, value_name = "MAX_PACKETS")]
    max_packets: Option<u64>,
    /// Maximum wire bytes authorized for one operation [default: 268435456].
    #[arg(long, value_name = "MAX_BYTES")]
    max_bytes: Option<u64>,
    /// Maximum distinct addresses accepted from one hostname resolution [default: 64].
    #[arg(long, value_name = "MAX_RESOLVED_ADDRESSES")]
    max_resolved_addresses: Option<usize>,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct ReplayPolicyArgs {
    /// Deliberately authorize globally routable destinations.
    #[arg(long)]
    allow_public_destinations: bool,
    /// Policy-level opt-in for malformed/permissive live bytes.
    #[arg(long)]
    allow_permissive_packets: bool,
    /// Maximum packets authorized for one operation.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(crate) max_packets: u64,
    /// Maximum wire bytes authorized for one operation.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(crate) max_bytes: u64,
}

impl TrafficPolicyArgs {
    /// The command-line half of the policy, independent of any file.
    pub(crate) fn overrides(&self) -> client::policy::Overrides {
        client::policy::Overrides {
            allow_public_destinations: self.allow_public_destinations,
            allow_hostname_resolution: self.allow_hostname_resolution,
            allow_permissive_packets: self.allow_permissive_packets,
            max_packets_per_operation: self.max_packets,
            max_bytes_per_operation: self.max_bytes,
            max_resolved_addresses: self.max_resolved_addresses,
        }
    }

    /// Resolves a policy, reading the named file when one was given.
    pub(crate) fn resolve_policy(self) -> Result<client::policy::Policy, CliError> {
        let overrides = self.overrides();
        let file = match &self.policy_file {
            Some(path) => Some(read_policy_file(path)?),
            None => None,
        };
        Ok(client::policy::Policy::resolve(file, overrides))
    }
}

impl ReplayPolicyArgs {
    pub(crate) fn into_policy(self) -> client::policy::Policy {
        client::policy::Policy {
            allow_public_destinations: self.allow_public_destinations,
            allow_permissive_packets: self.allow_permissive_packets,
            max_packets_per_operation: self.max_packets,
            max_bytes_per_operation: self.max_bytes,
            ..client::policy::Policy::default()
        }
    }
}
