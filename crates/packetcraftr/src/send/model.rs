// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use crate::Stats;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub destination: Option<IpAddr>,
    pub plan: packetcraftr_netio::route::Options,
    pub build: packetcraftr_core::build::Options,
    /// Second explicit opt-in required in addition to policy approval.
    pub allow_permissive_live: bool,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub sent: crate::SentPacket,
    pub stats: Stats,
}
