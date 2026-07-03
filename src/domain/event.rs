// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::SystemTime;

use crate::domain::net::MacAddress;

#[cfg(feature = "pcap")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolLabel {
    Tcp,
    Udp,
    Icmp,
    Sctp,
    Gre,
    Unknown,
}

#[cfg(feature = "pcap")]
impl ProtocolLabel {
    pub(crate) fn as_str(&self) -> &'static str {
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
pub(crate) struct ListenerEvent {
    pub timestamp: SystemTime,
    pub length: usize,
    pub layer2_source: Option<MacAddress>,
    pub layer2_destination: Option<MacAddress>,
    pub network_source: Option<IpAddr>,
    pub network_destination: Option<IpAddr>,
    pub network_protocol: Option<String>,
    pub transport: Option<String>,
    pub detail: Option<String>,
    #[cfg(feature = "pcap")]
    pub protocol_label: ProtocolLabel,
    pub data: Vec<u8>,
    pub show_payload: bool,
    pub truncated: bool,
}

#[cfg(all(test, feature = "pcap"))]
mod tests {
    use super::*;

    #[test]
    fn protocol_label_as_str_covers_all_variants() {
        assert_eq!(ProtocolLabel::Tcp.as_str(), "tcp");
        assert_eq!(ProtocolLabel::Udp.as_str(), "udp");
        assert_eq!(ProtocolLabel::Icmp.as_str(), "icmp");
        assert_eq!(ProtocolLabel::Sctp.as_str(), "sctp");
        assert_eq!(ProtocolLabel::Gre.as_str(), "gre");
        assert_eq!(ProtocolLabel::Unknown.as_str(), "unknown");
    }
}
