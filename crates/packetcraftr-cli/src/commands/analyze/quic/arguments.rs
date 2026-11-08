use crate::command_options::InterfaceSelector;
use crate::command_options::{
    CaptureLimitsArgs, DecodeArgs, LongTimeoutArgs, OfflineLimitsArgs, Selector, interface_selector,
};
use clap::{Args as ClapArgs, ValueEnum};
use packetcraftr_core::analysis::quic;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum Direction {
    #[default]
    Both,
    Client,
    Server,
}
impl Direction {
    pub(super) fn includes(self, direction: quic::Direction) -> bool {
        matches!(
            (self, direction),
            (Self::Both, _)
                | (Self::Client, quic::Direction::Client)
                | (Self::Server, quic::Direction::Server)
        )
    }
}
#[derive(Clone, Debug, ClapArgs)]
pub(crate) struct Args {
    #[arg(
        value_name = "PATH",
        required_unless_present = "interface",
        conflicts_with = "interface",
        help = "Read PCAP or PCAPNG, with - for stdin"
    )]
    pub path: Option<PathBuf>,
    #[arg(long="interface",value_parser=interface_selector,value_name="INTERFACE", conflicts_with="path", help="Capture from a native interface, repeatable")]
    pub interface: Vec<Selector<InterfaceSelector>>,
    #[arg(
        long,
        value_name = "PATH",
        help = "Read NSS TLS secrets, following appended records during live capture"
    )]
    pub keylog: Option<PathBuf>,
    #[arg(
        long,
        help = "Native numeric BPF filter, applied before capture queues"
    )]
    pub capture_filter: Option<String>,
    #[arg(long, help = "Enable promiscuous capture")]
    pub promiscuous: bool,
    #[arg(
        long,
        value_name = "EXPR",
        help = "Display filter, applied after IP reconstruction"
    )]
    pub filter: Option<String>,
    #[arg(
        long,
        help = "Select a capture-global QUIC connection index after reconstruction"
    )]
    pub connection: Option<u64>,
    #[arg(long, help = "Select a QUIC stream ID within selected connections")]
    pub stream: Option<u64>,
    #[arg(long,value_enum,default_value_t=Direction::Both,help="Select the sender of stream data")]
    pub direction: Direction,
    #[arg(long, help = "Include bounded hexadecimal stream payloads")]
    pub include_data: bool,
    #[arg(
        long,
        value_name = "DIR",
        help = "Export raw contiguous ranges and a gap-aware manifest into an existing directory"
    )]
    pub write: Option<PathBuf>,
    #[arg(long, default_value_t = 8192, help = "Maximum active QUIC connections")]
    pub max_connections: usize,
    #[arg(long,default_value_t=64*1024*1024,help="Maximum charged QUIC state bytes")]
    pub max_quic_buffered_bytes: usize,
    #[arg(long,default_value_t=1024*1024,help="Maximum retained bytes per stream direction")]
    pub max_quic_stream_bytes: usize,
    #[arg(
        long,
        default_value_t = 64,
        help = "Maximum pending encrypted packets per connection"
    )]
    pub max_pending_packets: usize,
    #[arg(
        long,
        default_value_t = 4096,
        help = "Maximum stream directions per connection"
    )]
    pub max_quic_streams: usize,
    #[arg(
        long,
        default_value_t = 120000,
        help = "Connection idle expiry in capture milliseconds"
    )]
    pub quic_idle_expiry_ms: u64,
    #[arg(
        long,
        default_value_t = 256,
        help = "Maximum aggregate report connections"
    )]
    pub max_output_connections: usize,
    #[arg(long,default_value_t=64*1024*1024,help="Maximum aggregate report, inline payload, and exported payload bytes")]
    pub max_application_output_bytes: usize,
    #[command(flatten)]
    pub timeout: LongTimeoutArgs,
    #[command(flatten)]
    pub capture: CaptureLimitsArgs,
    #[command(flatten)]
    pub decode: DecodeArgs,
    #[command(flatten)]
    pub limits: OfflineLimitsArgs,
}
impl Args {
    pub(super) fn quic_limits(&self) -> quic::Limits {
        quic::Limits {
            max_connections: self.max_connections,
            max_buffered_bytes: self.max_quic_buffered_bytes,
            max_stream_bytes: self.max_quic_stream_bytes,
            max_pending_packets: self.max_pending_packets,
            max_streams_per_connection: self.max_quic_streams,
            idle_expiry: Duration::from_millis(self.quic_idle_expiry_ms),
            ..quic::Limits::default()
        }
    }
}
