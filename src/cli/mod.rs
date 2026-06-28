pub mod commands;
pub mod enums;
pub mod options;
#[cfg(feature = "repl")]
pub(crate) mod repl;
mod request;
pub mod validators;

#[cfg(test)]
mod tests;

#[cfg(feature = "daemon")]
pub use commands::DaemonOptions;
#[cfg(feature = "fuzz")]
pub use commands::FuzzOptions;
#[cfg(feature = "repl")]
pub use commands::InteractiveOptions;
#[cfg(feature = "pcap")]
pub use commands::ListenCommandOptions;
#[cfg(feature = "scan")]
pub use commands::ScanCommand;
pub use commands::{DnsQueryOptions, PacketcraftCommand};
#[cfg(feature = "traceroute")]
pub use commands::{TracerouteOptions, TracerouteProtocol};
pub use enums::{FragmentProfile, Icmpv6ErrorCode, Icmpv6ErrorKind, LogLevel, OutputFormat};
pub use options::{
    IcmpOptions, Icmpv6Options, IpOptions, Layer2Options, ListenOptions, LoggingOptions,
    OneShotOptions, PayloadOptions, RuleOptions, SendOptions, TcpOptions, TransmitOptions,
    TransportCommand, TransportOptions, UdpOptions, VlanOptions,
};

use clap::Parser;

/// Top-level CLI arguments for PacketcraftR.
#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Modular packet crafting, transmission, and automation toolkit",
    long_about = "PacketcraftR builds packets layer-by-layer (Ethernet -> IP -> Transport -> Payload) for authorized lab, protocol-development, and network-testing work. \
The stable rescue surface focuses on safe dry-run previews, packet validation, and finite packet transmission planning. \
Advanced operational tools are experimental and appear only when their Cargo features are enabled.",
    after_help = "EXAMPLES:

  1. Preview a UDP payload to loopback without transmitting:
     packetcraftr dry-run -d 127.0.0.1 --data hello udp --dport 9

  2. Preview JSON output for automation:
     packetcraftr --output-format json dry-run -d 127.0.0.1 --data hello udp --dport 9

  3. Build an ICMP Echo Request preview:
     packetcraftr dry-run -d 127.0.0.1 icmp --icmp-type 8 --icmp-code 0

  4. Preview a raw payload from hex:
     packetcraftr dry-run -d 127.0.0.1 --data-hex \"aa bb cc\" udp --dport 9"
)]
pub struct PacketcraftArgs {
    /// Set the verbosity level (-v: info, -vv: debug, -vvv: trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Set the output format for display and logging.
    #[arg(long, value_enum)]
    pub output_format: Option<OutputFormat>,
    /// Preview what would be sent without transmitting any packets.
    #[arg(
        long,
        global = true,
        help = "Preview what would be sent without transmitting any packets"
    )]
    pub dry_run: bool,
    /// Select an operation mode.
    #[command(subcommand)]
    pub command: PacketcraftCommand,
}

impl PacketcraftArgs {
    pub fn one_shot_options(&self) -> Option<&OneShotOptions> {
        match &self.command {
            PacketcraftCommand::Send(options) | PacketcraftCommand::DryRun(options) => {
                Some(&options.oneshot)
            }
            _ => None,
        }
    }

    pub fn effective_dry_run(&self) -> bool {
        self.dry_run || matches!(&self.command, PacketcraftCommand::DryRun(_))
    }

    pub(crate) fn engine_config(&self) -> crate::engine::EngineConfig {
        let rule_options = match &self.command {
            #[cfg(feature = "daemon")]
            PacketcraftCommand::Daemon(opts) => Some(&opts.rule_options),
            _ => self.one_shot_options().map(|options| &options.rule),
        };
        let logging_options = self.one_shot_options().map(|options| &options.logging);

        crate::engine::EngineConfig {
            output_format: self.output_format.map(crate::output::OutputFormat::from),
            prometheus_bind: logging_options.and_then(|options| options.prometheus_bind.clone()),
            rule_workers: rule_options.and_then(|options| options.rule_workers),
            rule_queue: rule_options.and_then(|options| options.rule_queue),
            send_workers: rule_options.and_then(|options| options.send_workers),
            send_queue: rule_options.and_then(|options| options.send_queue),
            allow_unbounded_sends: rule_options
                .map(|options| options.allow_unbounded_sends)
                .unwrap_or(false),
            dry_run: self.effective_dry_run(),
        }
    }

    pub(crate) fn engine_command(&self) -> crate::engine::EngineCommand {
        match &self.command {
            PacketcraftCommand::Send(options) => crate::engine::EngineCommand::Send(
                crate::engine::request::PacketRequest::from(&options.oneshot),
            ),
            PacketcraftCommand::DryRun(options) => crate::engine::EngineCommand::DryRun(
                crate::engine::request::PacketRequest::from(&options.oneshot),
            ),
            #[cfg(feature = "repl")]
            PacketcraftCommand::Interactive(options) => {
                crate::engine::EngineCommand::Interactive(options.to_request())
            }
            #[cfg(feature = "daemon")]
            PacketcraftCommand::Daemon(options) => {
                crate::engine::EngineCommand::Daemon(options.to_request())
            }
            #[cfg(feature = "pcap")]
            PacketcraftCommand::Listen(options) => {
                crate::engine::EngineCommand::Listen(options.to_request())
            }
            #[cfg(feature = "traceroute")]
            PacketcraftCommand::Traceroute(options) => {
                crate::engine::EngineCommand::Traceroute(options.to_request())
            }
            #[cfg(feature = "scan")]
            PacketcraftCommand::Scan(command) => {
                crate::engine::EngineCommand::Scan(command.to_request())
            }
            PacketcraftCommand::DnsQuery(options) => {
                crate::engine::EngineCommand::DnsQuery(options.to_request())
            }
            #[cfg(feature = "fuzz")]
            PacketcraftCommand::Fuzz(options) => {
                crate::engine::EngineCommand::Fuzz(options.to_request())
            }
        }
    }
}
