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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn base_event() -> ListenerEvent {
        ListenerEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            length: 64,
            layer2_source: Some(MacAddr::new(0, 1, 2, 3, 4, 5)),
            layer2_destination: Some(MacAddr::new(6, 7, 8, 9, 10, 11)),
            network_source: None,
            network_destination: None,
            network_protocol: None,
            transport: None,
            detail: None,
            protocol_label: ProtocolLabel::Unknown,
            data: Vec::new(),
            show_payload: false,
            truncated: false,
        }
    }

    #[test]
    fn listener_event_rule_context_prefers_transport_and_network_addresses() {
        let mut event = base_event();
        event.network_source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        event.network_destination = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)));
        event.network_protocol = Some("ipv4".to_string());
        event.transport = Some("tcp".to_string());

        let context = listener_event_rule_context(&event);

        assert_eq!(context.description, "tcp");
        assert_eq!(context.source.as_deref(), Some("192.0.2.10"));
        assert_eq!(context.destination.as_deref(), Some("198.51.100.20"));
        assert_eq!(context.length, 64);
        assert_eq!(context.timestamp, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn listener_event_rule_context_falls_back_to_layer2_and_unknown_description() {
        let event = base_event();

        let context = listener_event_rule_context(&event);

        assert_eq!(context.description, "unknown packet");
        assert_eq!(context.source.as_deref(), Some("00:01:02:03:04:05"));
        assert_eq!(context.destination.as_deref(), Some("06:07:08:09:0a:0b"));
    }
}
