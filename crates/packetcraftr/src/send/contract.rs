// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use super::super::Stats;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub destination: Option<IpAddr>,
    pub plan: packetcraftr_netio::route::Options,
    pub build: packetcraftr_core::build::Options,
    /// Per-operation confirmation required in addition to policy approval.
    pub confirm_live_opt_in: bool,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub sent: crate::SentPacket,
    pub stats: Stats,
}
