// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Deserialize;
use std::time::SystemTime;

use crate::domain::event::ListenerEvent;

#[derive(Debug, Clone)]
pub(crate) struct PacketContext {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::event::ListenerEvent;
    use crate::domain::net::MacAddress;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn listener_event() -> ListenerEvent {
        ListenerEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            length: 64,
            layer2_source: Some(MacAddress::from_str("00:11:22:33:44:55").unwrap()),
            layer2_destination: Some(MacAddress::from_str("66:77:88:99:aa:bb").unwrap()),
            network_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            network_destination: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            network_protocol: Some("IPv6".to_string()),
            transport: Some("TCP".to_string()),
            detail: Some("detail".to_string()),
            #[cfg(feature = "pcap")]
            protocol_label: crate::domain::event::ProtocolLabel::Tcp,
            data: vec![0xde, 0xad],
            show_payload: true,
            truncated: false,
        }
    }

    #[test]
    fn packet_context_from_listener_event_prefers_transport_and_network_addresses() {
        let event = listener_event();

        let packet = PacketContext::from_listener_event(&event);

        assert_eq!(packet.description, "TCP");
        assert_eq!(packet.source.as_deref(), Some("192.0.2.10"));
        assert_eq!(packet.destination.as_deref(), Some("::1"));
        assert_eq!(packet.length, 64);
        assert_eq!(packet.timestamp, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn packet_context_from_listener_event_falls_back_to_network_protocol_and_layer2() {
        let mut event = listener_event();
        event.transport = None;
        event.network_source = None;
        event.network_destination = None;

        let packet = PacketContext::from_listener_event(&event);

        assert_eq!(packet.description, "IPv6");
        assert_eq!(packet.source.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(packet.destination.as_deref(), Some("66:77:88:99:aa:bb"));
    }

    #[test]
    fn packet_context_from_listener_event_uses_unknown_without_protocols() {
        let mut event = listener_event();
        event.transport = None;
        event.network_protocol = None;

        let packet = PacketContext::from_listener_event(&event);

        assert_eq!(packet.description, "unknown packet");
    }
}

#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RuleLogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}
