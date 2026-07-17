// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Declared target before hostname resolution or traffic-policy effects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Target {
    Address(IpAddr),
    Hostname(String),
}

impl fmt::Display for Target {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(address) => address.fmt(formatter),
            Self::Hostname(hostname) => formatter.write_str(hostname),
        }
    }
}

/// Target whose declared name and selected addresses have been authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorized {
    pub declared: String,
    pub addresses: Vec<IpAddr>,
}

/// Policy and resolution seam shared by scan, DNS, and traceroute.
pub trait Authorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
    ) -> Result<Authorized, super::BoundaryError>;

    fn authorize_operation(
        &mut self,
        packets: u64,
        maximum_wire_bytes: u64,
    ) -> Result<(), super::BoundaryError>;
}
