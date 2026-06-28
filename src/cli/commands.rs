#[cfg(any(
    feature = "daemon",
    feature = "pcap",
    feature = "repl",
    feature = "traceroute"
))]
use clap::builder::BoolishValueParser;
#[cfg(any(feature = "fuzz", feature = "traceroute"))]
use clap::ValueEnum;
use clap::{value_parser, Args, Subcommand};

#[cfg(feature = "pcap")]
use super::options::ListenOptions;
#[cfg(feature = "daemon")]
use super::options::RuleOptions;
use super::options::SendOptions;
use super::validators::dns_record_type_validator;
use crate::engine::command::DnsTransportMode;

/// Global operation modes.
#[derive(Debug, Subcommand)]
pub enum PacketcraftCommand {
    /// Send a finite packet request.
    Send(SendOptions),
    /// Preview a packet request without transmitting.
    DryRun(SendOptions),
    /// Start the interactive REPL shell.
    #[cfg(feature = "repl")]
    Interactive(InteractiveOptions),
    /// Run as a background daemon with automation.
    #[cfg(feature = "daemon")]
    Daemon(DaemonOptions),
    /// Listen for network packets and react.
    #[cfg(feature = "pcap")]
    Listen(ListenCommandOptions),
    /// Map network routes (traceroute).
    #[cfg(feature = "traceroute")]
    Traceroute(TracerouteOptions),
    /// Execute network scans (TCP SYN, UDP, etc.).
    #[command(subcommand)]
    #[cfg(feature = "scan")]
    Scan(ScanCommand),
    /// Perform a DNS query.
    DnsQuery(DnsQueryOptions),
    /// Fuzz a target with malformed packets.
    #[cfg(feature = "fuzz")]
    Fuzz(FuzzOptions),
}

#[cfg(feature = "fuzz")]
#[derive(Debug, Args, Clone)]
pub struct FuzzOptions {
    /// Target IP address (IPv4/IPv6).
    #[arg(long = "target")]
    pub target: String,

    /// Target port (required for TCP/UDP).
    #[arg(
        long = "port",
        required_if_eq("protocol", "tcp"),
        required_if_eq("protocol", "udp")
    )]
    pub port: Option<u16>,

    /// Select the protocol to fuzz.
    #[arg(long = "protocol", value_enum)]
    pub protocol: FuzzProtocol,

    /// Select the fuzzing strategy.
    #[arg(long = "strategy", value_enum, default_value_t = FuzzStrategy::RandomPayload)]
    pub strategy: FuzzStrategy,

    /// Number of packets to send.
    #[arg(long = "count", default_value_t = 100)]
    pub count: u64,

    /// Delay between packets (in ms).
    #[arg(long = "delay", default_value_t = 10)]
    pub delay: u64,
}

#[cfg(feature = "fuzz")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FuzzProtocol {
    /// Fuzz TCP protocol fields.
    Tcp,
    /// Fuzz UDP payload and headers.
    Udp,
    /// Fuzz ICMP packet structures.
    Icmp,
}

#[cfg(feature = "fuzz")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FuzzStrategy {
    /// Randomly flip bits in the payload.
    BitFlip,
    /// Randomly swap bytes in the payload.
    ByteSwap,
    /// Replace payload with random bytes.
    #[value(alias = "random")]
    RandomPayload,
    /// Test boundary values (empty, max size).
    #[value(alias = "byte-overflow")]
    Boundary,
}

#[derive(Debug, Args, Clone, Default)]
pub struct DnsQueryOptions {
    /// Domain to query.
    #[arg(long = "domain")]
    pub domain: String,
    /// DNS record type.
    #[arg(long = "type", default_value = "A", value_parser = dns_record_type_validator)]
    pub record_type: String,
    /// DNS server IP.
    #[arg(long = "server", default_value = "8.8.8.8")]
    pub server: String,
    /// Query timeout (in ms).
    #[arg(long = "timeout", value_parser = value_parser!(u64), default_value_t = 1000)]
    pub timeout: u64,
    /// DNS Transaction ID.
    #[arg(long = "tid")]
    pub transaction_id: Option<u16>,
    /// DNS transport to use.
    #[arg(long = "transport", value_parser = value_parser!(DnsTransportMode), default_value_t = DnsTransportMode::Auto)]
    pub transport: DnsTransportMode,
    /// Extra attempts after the first attempt.
    #[arg(long = "retries", value_parser = value_parser!(u8).range(0..=5), default_value_t = 0)]
    pub retries: u8,
}

#[cfg(feature = "repl")]
#[derive(Debug, Args)]
pub struct InteractiveOptions {
    /// Preload a script file.
    #[arg(long = "script")]
    pub script: Option<String>,
    /// Automatically listen for replies.
    #[arg(
        long = "auto-listen",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub auto_listen: Option<bool>,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Args)]
pub struct DaemonOptions {
    #[command(flatten)]
    pub rule_options: RuleOptions,
    /// Run in the foreground.
    #[arg(
        long = "foreground",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub foreground: Option<bool>,
    /// Control socket path.
    #[arg(long = "control-socket")]
    #[cfg_attr(not(unix), arg(hide = true))]
    pub control_socket: Option<String>,
}

#[cfg(feature = "pcap")]
#[derive(Debug, Args)]
pub struct ListenCommandOptions {
    #[command(flatten, next_help_heading = "Listener configuration")]
    pub listen: ListenOptions,
    /// Continue listening after timeout.
    #[arg(
        long = "persistent",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub persistent: Option<bool>,
}

#[cfg(feature = "traceroute")]
#[derive(Debug, Args, Clone, Default)]
pub struct TracerouteOptions {
    /// Target destination.
    #[arg(long = "dest")]
    pub destination: String,
    /// Maximum TTL.
    #[arg(long = "max-ttl", value_parser = value_parser!(u8), default_value_t = 30)]
    pub max_ttl: u8,
    /// Number of probes per hop.
    #[arg(long = "probes", value_parser = value_parser!(u8), default_value_t = 3)]
    pub probes: u8,
    /// Probe protocol.
    #[arg(long = "protocol", value_enum, default_value_t = TracerouteProtocol::Udp)]
    pub protocol: TracerouteProtocol,
    /// Disable reverse DNS resolution.
    #[arg(
        long = "no-dns",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub no_dns: Option<bool>,
    /// Probe timeout (in ms).
    #[arg(long = "timeout", value_parser = value_parser!(u64), default_value_t = 3000)]
    pub timeout: u64,
}

#[cfg(feature = "traceroute")]
#[derive(Debug, Copy, Clone, ValueEnum, Default)]
pub enum TracerouteProtocol {
    /// Use UDP probes.
    #[default]
    Udp,
    /// Use TCP SYN probes.
    Tcp,
    /// Use ICMP Echo probes.
    Icmp,
}

#[cfg(feature = "scan")]
#[derive(Debug, Subcommand)]
pub enum ScanCommand {
    /// Perform a TCP SYN scan (half-open).
    TcpSyn {
        /// Target IP or CIDR (e.g., 192.168.1.0/24).
        #[arg(long = "target")]
        target: String,
        /// Ports to scan (e.g., "80,443", "1-100").
        #[arg(long = "ports")]
        ports: String,
        /// Scanning interface.
        #[arg(long = "interface")]
        interface: Option<String>,
    },
    /// Perform a TCP FIN scan (inverse mapping).
    TcpFin {
        /// Target IP or CIDR (e.g., 192.168.1.0/24).
        #[arg(long = "target")]
        target: String,
        /// Ports to scan (e.g., "80,443", "1-100").
        #[arg(long = "ports")]
        ports: String,
        /// Scanning interface.
        #[arg(long = "interface")]
        interface: Option<String>,
    },
    /// Perform a TCP NULL scan (no flags set).
    TcpNull {
        /// Target IP or CIDR (e.g., 192.168.1.0/24).
        #[arg(long = "target")]
        target: String,
        /// Ports to scan (e.g., "80,443", "1-100").
        #[arg(long = "ports")]
        ports: String,
        /// Scanning interface.
        #[arg(long = "interface")]
        interface: Option<String>,
    },
    /// Perform a TCP XMAS scan (FIN+URG+PUSH).
    TcpXmas {
        /// Target IP or CIDR (e.g., 192.168.1.0/24).
        #[arg(long = "target")]
        target: String,
        /// Ports to scan (e.g., "80,443", "1-100").
        #[arg(long = "ports")]
        ports: String,
        /// Scanning interface.
        #[arg(long = "interface")]
        interface: Option<String>,
    },
    /// Perform a TCP ACK scan (firewall mapping).
    TcpAck {
        /// Target IP or CIDR (e.g., 192.168.1.0/24).
        #[arg(long = "target")]
        target: String,
        /// Ports to scan (e.g., "80,443", "1-100").
        #[arg(long = "ports")]
        ports: String,
        /// Scanning interface.
        #[arg(long = "interface")]
        interface: Option<String>,
    },
    /// Perform an SCTP INIT scan.
    SctpInit {
        /// Target IP or CIDR (e.g., 192.168.1.0/24).
        #[arg(long = "target")]
        target: String,
        /// Ports to scan (e.g., "80,443", "1-100").
        #[arg(long = "ports")]
        ports: String,
        /// Scanning interface.
        #[arg(long = "interface")]
        interface: Option<String>,
    },
    /// Perform an ICMP echo scan (ping sweep).
    Icmp {
        /// Target IP or CIDR (e.g., 192.168.1.0/24).
        #[arg(long = "target")]
        target: String,
        /// Scanning interface.
        #[arg(long = "interface")]
        interface: Option<String>,
        /// Timeout (in ms).
        #[arg(long = "timeout", value_parser = value_parser!(u64), default_value_t = 1_000)]
        timeout: u64,
    },
    /// Perform a UDP scan.
    Udp {
        /// Target IP or CIDR (e.g., 192.168.1.0/24).
        #[arg(long = "target")]
        target: String,
        /// Ports to scan (e.g., "53", "1-100").
        #[arg(long = "ports")]
        ports: String,
        /// Scanning interface.
        #[arg(long = "interface")]
        interface: Option<String>,
    },
    /// Perform an ARP scan (local network discovery).
    Arp {
        /// Target IP or CIDR (e.g., 192.168.1.0/24).
        #[arg(long = "target")]
        target: String,
        /// Scanning interface.
        #[arg(long = "interface")]
        interface: Option<String>,
        /// Timeout (in ms).
        #[arg(long = "timeout", value_parser = value_parser!(u64), default_value_t = 1_000)]
        timeout: u64,
    },
    /// Perform an NDP scan (IPv6 local network discovery).
    Ndp {
        /// Target IP or CIDR (e.g., "fe80::/64").
        #[arg(long = "target")]
        target: String,
        /// Scanning interface.
        #[arg(long = "interface")]
        interface: Option<String>,
        /// Timeout (in ms).
        #[arg(long = "timeout", value_parser = value_parser!(u64), default_value_t = 1_000)]
        timeout: u64,
    },
}

impl DnsQueryOptions {
    pub(crate) fn to_request(&self) -> crate::engine::command::DnsRequest {
        crate::engine::command::DnsRequest {
            domain: self.domain.clone(),
            record_type: self.record_type.clone(),
            server: self.server.clone(),
            timeout: self.timeout,
            transaction_id: self.transaction_id,
            transport: self.transport,
            retries: self.retries,
        }
    }
}

#[cfg(feature = "repl")]
impl InteractiveOptions {
    pub(crate) fn to_request(&self) -> crate::engine::command::InteractiveRequest {
        crate::engine::command::InteractiveRequest {
            script: self.script.clone(),
            auto_listen: self.auto_listen,
        }
    }
}

#[cfg(feature = "daemon")]
impl DaemonOptions {
    pub(crate) fn to_request(&self) -> crate::engine::command::DaemonRequest {
        crate::engine::command::DaemonRequest {
            rules_file: self.rule_options.rules_file.clone(),
            foreground: self.foreground,
            control_socket: self.control_socket.clone(),
        }
    }
}

#[cfg(feature = "pcap")]
impl ListenCommandOptions {
    pub(crate) fn to_request(&self) -> crate::engine::command::ListenRequest {
        crate::engine::command::ListenRequest {
            listen: crate::engine::request::ListenerRequest::from(&self.listen),
            persistent: self.persistent,
        }
    }
}

#[cfg(feature = "traceroute")]
impl TracerouteOptions {
    pub(crate) fn to_request(&self) -> crate::engine::command::TracerouteRequest {
        crate::engine::command::TracerouteRequest {
            destination: self.destination.clone(),
            max_ttl: self.max_ttl,
            probes: self.probes,
            protocol: match self.protocol {
                TracerouteProtocol::Udp => crate::engine::command::TracerouteProtocol::Udp,
                TracerouteProtocol::Tcp => crate::engine::command::TracerouteProtocol::Tcp,
                TracerouteProtocol::Icmp => crate::engine::command::TracerouteProtocol::Icmp,
            },
            no_dns: self.no_dns,
            timeout: self.timeout,
        }
    }
}

#[cfg(feature = "scan")]
impl ScanCommand {
    pub(crate) fn to_request(&self) -> crate::engine::command::ScanRequest {
        use crate::engine::command::ScanRequest;

        match self {
            Self::TcpSyn {
                target,
                ports,
                interface,
            } => {
                let fields = PortScanRequestFields::from_cli(target, ports, interface);
                ScanRequest::TcpSyn {
                    target: fields.target,
                    ports: fields.ports,
                    interface: fields.interface,
                }
            }
            Self::TcpFin {
                target,
                ports,
                interface,
            } => {
                let fields = PortScanRequestFields::from_cli(target, ports, interface);
                ScanRequest::TcpFin {
                    target: fields.target,
                    ports: fields.ports,
                    interface: fields.interface,
                }
            }
            Self::TcpNull {
                target,
                ports,
                interface,
            } => {
                let fields = PortScanRequestFields::from_cli(target, ports, interface);
                ScanRequest::TcpNull {
                    target: fields.target,
                    ports: fields.ports,
                    interface: fields.interface,
                }
            }
            Self::TcpXmas {
                target,
                ports,
                interface,
            } => {
                let fields = PortScanRequestFields::from_cli(target, ports, interface);
                ScanRequest::TcpXmas {
                    target: fields.target,
                    ports: fields.ports,
                    interface: fields.interface,
                }
            }
            Self::TcpAck {
                target,
                ports,
                interface,
            } => {
                let fields = PortScanRequestFields::from_cli(target, ports, interface);
                ScanRequest::TcpAck {
                    target: fields.target,
                    ports: fields.ports,
                    interface: fields.interface,
                }
            }
            Self::SctpInit {
                target,
                ports,
                interface,
            } => {
                let fields = PortScanRequestFields::from_cli(target, ports, interface);
                ScanRequest::SctpInit {
                    target: fields.target,
                    ports: fields.ports,
                    interface: fields.interface,
                }
            }
            Self::Icmp {
                target,
                interface,
                timeout,
            } => {
                let fields = TargetScanRequestFields::from_cli(target, interface);
                ScanRequest::Icmp {
                    target: fields.target,
                    interface: fields.interface,
                    timeout: *timeout,
                }
            }
            Self::Udp {
                target,
                ports,
                interface,
            } => {
                let fields = PortScanRequestFields::from_cli(target, ports, interface);
                ScanRequest::Udp {
                    target: fields.target,
                    ports: fields.ports,
                    interface: fields.interface,
                }
            }
            Self::Arp {
                target,
                interface,
                timeout,
            } => {
                let fields = TargetScanRequestFields::from_cli(target, interface);
                ScanRequest::Arp {
                    target: fields.target,
                    interface: fields.interface,
                    timeout: *timeout,
                }
            }
            Self::Ndp {
                target,
                interface,
                timeout,
            } => {
                let fields = TargetScanRequestFields::from_cli(target, interface);
                ScanRequest::Ndp {
                    target: fields.target,
                    interface: fields.interface,
                    timeout: *timeout,
                }
            }
        }
    }
}

#[cfg(feature = "scan")]
struct PortScanRequestFields {
    target: String,
    ports: String,
    interface: Option<String>,
}

#[cfg(feature = "scan")]
impl PortScanRequestFields {
    fn from_cli(target: &str, ports: &str, interface: &Option<String>) -> Self {
        Self {
            target: target.to_owned(),
            ports: ports.to_owned(),
            interface: interface.clone(),
        }
    }
}

#[cfg(feature = "scan")]
struct TargetScanRequestFields {
    target: String,
    interface: Option<String>,
}

#[cfg(feature = "scan")]
impl TargetScanRequestFields {
    fn from_cli(target: &str, interface: &Option<String>) -> Self {
        Self {
            target: target.to_owned(),
            interface: interface.clone(),
        }
    }
}

#[cfg(feature = "fuzz")]
impl FuzzOptions {
    pub(crate) fn to_request(&self) -> crate::engine::command::FuzzRequest {
        crate::engine::command::FuzzRequest {
            target: self.target.clone(),
            port: self.port,
            protocol: match self.protocol {
                FuzzProtocol::Tcp => crate::engine::command::FuzzProtocol::Tcp,
                FuzzProtocol::Udp => crate::engine::command::FuzzProtocol::Udp,
                FuzzProtocol::Icmp => crate::engine::command::FuzzProtocol::Icmp,
            },
            strategy: match self.strategy {
                FuzzStrategy::BitFlip => crate::engine::command::FuzzStrategy::BitFlip,
                FuzzStrategy::ByteSwap => crate::engine::command::FuzzStrategy::ByteSwap,
                FuzzStrategy::RandomPayload => crate::engine::command::FuzzStrategy::RandomPayload,
                FuzzStrategy::Boundary => crate::engine::command::FuzzStrategy::Boundary,
            },
            count: self.count,
            delay: self.delay,
        }
    }
}
