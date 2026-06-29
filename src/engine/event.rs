// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::SystemTime;

use pnet::datalink::MacAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolLabel {
    Tcp,
    Udp,
    Icmp,
    Sctp,
    Gre,
    Unknown,
}

impl ProtocolLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Sctp => "sctp",
            Self::Gre => "gre",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ListenerEvent {
    pub timestamp: SystemTime,
    pub length: usize,
    pub layer2_source: Option<MacAddr>,
    pub layer2_destination: Option<MacAddr>,
    pub network_source: Option<IpAddr>,
    pub network_destination: Option<IpAddr>,
    pub network_protocol: Option<String>,
    pub transport: Option<String>,
    pub detail: Option<String>,
    pub protocol_label: ProtocolLabel,
    pub data: Vec<u8>,
    pub show_payload: bool,
    pub truncated: bool,
}

pub(crate) fn listener_event_rule_context(event: &ListenerEvent) -> crate::rules::PacketContext {
    crate::rules::PacketContext {
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
