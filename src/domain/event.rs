// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::SystemTime;

use crate::domain::net::MacAddress;

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
    pub layer2_source: Option<MacAddress>,
    pub layer2_destination: Option<MacAddress>,
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
