// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Deserialize;
use std::time::SystemTime;

use crate::domain::event::ListenerEvent;

#[derive(Debug, Clone)]
pub struct PacketContext {
    pub description: String,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub length: usize,
    pub timestamp: SystemTime,
}

impl PacketContext {
    pub(crate) fn from_listener_event(event: &ListenerEvent) -> Self {
        Self {
            description: event
                .transport
                .clone()
                .or_else(|| event.network_protocol.clone())
                .unwrap_or_else(|| "unknown packet".to_string()),
            source: event
                .network_source
                .map(|ip| ip.to_string())
                .or_else(|| event.layer2_source.map(|mac| mac.to_string())),
            destination: event
                .network_destination
                .map(|ip| ip.to_string())
                .or_else(|| event.layer2_destination.map(|mac| mac.to_string())),
            length: event.length,
            timestamp: event.timestamp,
        }
    }
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
