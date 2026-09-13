// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub path: String,
    pub rule_matches: Vec<u64>,
    #[serde(flatten)]
    pub capture: packetcraftr_core::analysis::pcap::MapReport,
}
