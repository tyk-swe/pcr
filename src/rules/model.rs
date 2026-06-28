// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Deserialize;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct PacketContext {
    pub description: String,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub length: usize,
    pub timestamp: SystemTime,
}

#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleLogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}
