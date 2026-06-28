// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "pcap")]
use crate::engine::request::ListenerRequest;
use crate::engine::request::PacketRequest;

#[derive(Debug, Clone)]
pub enum EngineCommand {
    Send(PacketRequest),
    DryRun(PacketRequest),
    #[cfg(feature = "repl")]
    Interactive(InteractiveRequest),
    #[cfg(feature = "daemon")]
    Daemon(DaemonRequest),
    #[cfg(feature = "pcap")]
    Listen(ListenRequest),
    #[cfg(feature = "traceroute")]
    Traceroute(TracerouteRequest),
    #[cfg(feature = "scan")]
    Scan(ScanRequest),
    DnsQuery(DnsRequest),
    #[cfg(feature = "fuzz")]
    Fuzz(FuzzRequest),
}

#[derive(Debug, Clone, Default)]
pub struct DnsRequest {
    pub domain: String,
    pub record_type: String,
    pub server: String,
    pub timeout: u64,
    pub transaction_id: Option<u16>,
    pub transport: DnsTransportMode,
    pub retries: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DnsTransportMode {
    #[default]
    Auto,
    Udp,
    Tcp,
}

impl DnsTransportMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

impl std::fmt::Display for DnsTransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DnsTransportMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            _ => Err(format!(
                "unsupported DNS transport: {value} (valid values: auto, udp, tcp)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTransport {
    Udp,
    Tcp,
}

impl DnsTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

impl std::fmt::Display for DnsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct DnsQueryResult {
    pub message: trust_dns_proto::op::Message,
    pub transport_used: DnsTransport,
    pub attempts: u32,
    pub server: String,
    pub response_bytes: usize,
    pub udp_truncated: bool,
    pub tcp_fallback_used: bool,
}

#[cfg(feature = "scan")]
#[derive(Debug, Clone)]
pub enum ScanRequest {
    TcpSyn {
        target: String,
        ports: String,
        interface: Option<String>,
    },
    TcpFin {
        target: String,
        ports: String,
        interface: Option<String>,
    },
    TcpNull {
        target: String,
        ports: String,
        interface: Option<String>,
    },
    TcpXmas {
        target: String,
        ports: String,
        interface: Option<String>,
    },
    TcpAck {
        target: String,
        ports: String,
        interface: Option<String>,
    },
    SctpInit {
        target: String,
        ports: String,
        interface: Option<String>,
    },
    Icmp {
        target: String,
        interface: Option<String>,
        timeout: u64,
    },
    Udp {
        target: String,
        ports: String,
        interface: Option<String>,
    },
    Arp {
        target: String,
        interface: Option<String>,
        timeout: u64,
    },
    Ndp {
        target: String,
        interface: Option<String>,
        timeout: u64,
    },
}

#[cfg(feature = "traceroute")]
#[derive(Debug, Clone, Default)]
pub struct TracerouteRequest {
    pub destination: String,
    pub max_ttl: u8,
    pub probes: u8,
    pub protocol: TracerouteProtocol,
    pub no_dns: Option<bool>,
    pub timeout: u64,
}

#[cfg(feature = "traceroute")]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum TracerouteProtocol {
    #[default]
    Udp,
    Tcp,
    Icmp,
}

#[cfg(feature = "fuzz")]
#[derive(Debug, Clone)]
pub struct FuzzRequest {
    pub target: String,
    pub port: Option<u16>,
    pub protocol: FuzzProtocol,
    pub strategy: FuzzStrategy,
    pub count: u64,
    pub delay: u64,
}

#[cfg(feature = "fuzz")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzProtocol {
    Tcp,
    Udp,
    Icmp,
}

#[cfg(feature = "fuzz")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzStrategy {
    BitFlip,
    ByteSwap,
    RandomPayload,
    Boundary,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Clone, Default)]
pub struct DaemonRequest {
    pub rules_file: Option<String>,
    pub foreground: Option<bool>,
    pub control_socket: Option<String>,
}

#[cfg(feature = "repl")]
#[derive(Debug, Clone, Default)]
pub struct InteractiveRequest {
    pub script: Option<String>,
    pub auto_listen: Option<bool>,
}

#[cfg(feature = "pcap")]
#[derive(Debug, Clone, Default)]
pub struct ListenRequest {
    pub listen: ListenerRequest,
    pub persistent: Option<bool>,
}
