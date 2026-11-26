// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::route;

/// How every packet of one send is routed, built, and authorized on its way to the wire.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub destination: Option<std::net::IpAddr>,
    pub plan: route::Options,
    pub build: packetcraftr_core::build::Options,
    /// Second explicit opt-in required in addition to policy approval.
    pub allow_permissive_live: bool,
}
