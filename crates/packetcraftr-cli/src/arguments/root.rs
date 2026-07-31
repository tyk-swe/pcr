// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::{Parser, Subcommand, ValueEnum};
use packetcraftr::output;

use super::{
    BuildArgs, CaptureArgs, DissectArgs, DnsArgs, ExchangeArgs, ExpertArgs, FollowArgs, FuzzArgs,
    ProtocolsArgs, ReadArgs, ReplayArgs, RouteArgs, ScanArgs, SendArgs, StatsArgs, TracerouteArgs,
};

const ROOT_AFTER_HELP: &str = r#"Output formats:
  text    Human-readable summaries and diagnostics.
  json    One aggregate JSON document.
  ndjson  One JSON record per streamed event.
  hex     Exact frame bytes as hexadecimal text.
  raw     Exact frame bytes without text framing.
  pcap    Classic PCAP capture bytes.
  pcapng  PCAPNG capture bytes.

Output availability is command-specific. Machine formats never contain terminal colour codes.

Examples:
  packetcraftr build --packet 'raw(text=hello)'
  packetcraftr --output json dissect --hex '45000014000000004001f6e7c0000201c6336402'
  packetcraftr --output ndjson read capture.pcapng --max-frames 100

Run `packetcraftr <COMMAND> --help` for command-specific options and examples."#;
const BUILD_AFTER_HELP: &str = r#"Examples:
  packetcraftr build --packet 'raw(text=hello)'
  packetcraftr --output raw build --packet-file packet.json"#;
const DISSECT_AFTER_HELP: &str = r#"When neither --hex nor --file is supplied, raw frame bytes are read from standard input.

With --filter, the dissection is emitted only when the frame matches; a frame that does not match emits nothing and the command still succeeds.

Examples:
  packetcraftr dissect --hex '45000014000000004001f6e7c0000201c6336402'
  packetcraftr --output json dissect --file frame.bin --link-type 1
  packetcraftr dissect --file frame.bin --filter 'icmpv4 && ip.dst == 198.51.100.2'"#;
const PROTOCOLS_AFTER_HELP: &str = r#"Examples:
  packetcraftr protocols
  packetcraftr protocols ipv4
  packetcraftr --output json protocols IP4"#;
const READ_AFTER_HELP: &str = r#"Examples:
  packetcraftr read capture.pcapng --max-frames 100
  packetcraftr --output ndjson read capture.pcap
  packetcraftr read capture.pcapng --filter 'tcp.flags.syn == 1 && !tcp.flags.ack' --dissect
  packetcraftr --output pcapng read capture.pcapng --filter 'ip.src in 10.0.0.0/8' > subset.pcapng"#;
const INTERFACES_AFTER_HELP: &str = r#"Examples:
  packetcraftr interfaces
  packetcraftr --output json interfaces"#;
const PLAN_AFTER_HELP: &str = r#"Route planning is passive: it performs no packet transmission.

Example:
  packetcraftr plan --packet 'ipv4(dst=192.0.2.53)/udp(dport=53)'"#;
const SEND_AFTER_HELP: &str = r#"Live transmission is policy-gated and may require native features, dependencies, and privileges.

Example:
  packetcraftr send --packet 'ipv4(dst=192.0.2.1)/icmpv4(type=8,code=0)'"#;
const EXCHANGE_AFTER_HELP: &str = r#"Live exchange is policy-gated and may require native features, dependencies, and privileges.

Example:
  packetcraftr exchange --packet 'ipv4(dst=192.0.2.1)/icmpv4(type=8,code=0)' --timeout-ms 1000"#;
const CAPTURE_AFTER_HELP: &str = r#"Live capture may require native features, dependencies, and privileges.

--capture-filter <BPF> uses the stable resolver-free core of libpcap/Npcap BPF syntax and narrows what reaches PacketcraftR. Frames it rejects never enter PacketcraftR's capture queue and do not consume queue capacity or operation frame and byte budgets.

Use core BPF keywords and numeric address, network, port, and protocol operands. Other symbolic tokens are rejected before native compilation so capture filters cannot perform hidden hostname or name-database resolution; --allow-hostname-resolution does not change this rule.

--filter <EXPR> uses PacketcraftR's display-filter language after capture. Frames it rejects have already occupied PacketcraftR's capture queue and passed the native BPF filter, so they still consume operation frame and byte budgets.

The two filters use different languages and may be combined.

Examples:
  packetcraftr capture --packet 'ipv4(dst=192.0.2.53)/udp(dport=53)' --timeout-ms 1000
  packetcraftr capture \
    --packet 'ipv4(dst=192.0.2.53)/udp(dport=53)' \
    --capture-filter 'udp port 53' \
    --filter 'udp.source_port == 53'"#;
const REPLAY_AFTER_HELP: &str = r#"Replay is policy-gated and may require native features, dependencies, and privileges.

Frames a --filter rejects are skipped before authorization, so they are never policy-checked or transmitted, but they still count against the operation's frame budget. Transmitted frames keep their original spacing: the delay before a kept frame spans any skipped frames in between.

Examples:
  packetcraftr replay capture.pcapng --interface eth0 --timing immediate
  packetcraftr replay capture.pcap --interface 2 --rate 100
  packetcraftr replay capture.pcap --interface eth0 --filter 'udp && ip.dst == 10.0.0.2'"#;
const SCAN_AFTER_HELP: &str = r#"Examples:
  packetcraftr scan 192.0.2.10 --transport tcp --ports 22,80,443
  packetcraftr --output ndjson scan 198.51.100.10 --transport icmp"#;
const FOLLOW_AFTER_HELP: &str = r#"Following is computed offline over dissected frames; no live capture or transmission is involved.

The conversation index comes from the same first-seen numbering stats reports and stream filters match, so 'follow --stream tcp:7' extracts the conversation 'tcp.stream == 7' selects. The client is the endpoint that sent the conversation's first captured frame. TCP payload is reassembled in stream order per direction; UDP emits one chunk per datagram. IP-fragmented datagrams carry no conversation index and are not followed. Raw output needs a single direction, since interleaved raw bytes would be indistinguishable.

Examples:
  packetcraftr follow capture.pcapng --stream tcp:0
  packetcraftr follow capture.pcapng --stream tcp:0 --direction client --output raw > client.bin
  packetcraftr --output json follow capture.pcapng --stream udp:2"#;
const EXPERT_AFTER_HELP: &str = r#"Expert analysis is computed offline over dissected frames; no live capture or transmission is involved.

Retransmissions (including retransmissions whose content changed) come from bounded TCP reassembly, and duplicate acknowledgments, zero windows and their probes, window-full and window-exceeded conditions, keep-alives, resets, and uncaptured earlier segments come from cross-frame header tracking. Dissection diagnostics such as checksum mismatches surface as findings under their own codes. IPv4/IPv6 fragment overlap, gap, and incomplete states; correlated ICMP errors; and interface/VLAN-scoped ARP address conflicts are also reported. Stream-aware filters such as 'tcp.stream == 7' are supported.

Examples:
  packetcraftr expert capture.pcapng
  packetcraftr expert capture.pcapng --filter 'tcp.stream == 3'
  packetcraftr --output ndjson expert capture.pcapng"#;
const STATS_AFTER_HELP: &str = r#"Statistics are computed offline over dissected frames; no live capture or transmission is involved.

Conversation (stream) indices are assigned in first-seen order over the whole capture before any --filter runs, so the index one invocation reports names the same conversation in every other invocation, and stream-aware filters such as 'tcp.stream == 7' are supported.

The lengths table buckets original on-wire frame lengths, not captured lengths. The service-response-time table is a generic matched-frame request-burst heuristic, not protocol-aware transaction correlation: TCP handshake roles are used when available and otherwise the first matched sender is the requester, while UDP uses its first sender, including empty datagrams. Inferred roles and samples use only frames kept by --filter. TCP control-only packets do not produce response-time samples.

Examples:
  packetcraftr stats capture.pcapng --table conversations
  packetcraftr stats capture.pcapng --table protocols --filter 'ip.src in 10.0.0.0/8'
  packetcraftr --output json stats capture.pcapng --table io --interval-ms 100
  packetcraftr stats capture.pcapng --table lengths
  packetcraftr stats capture.pcapng --table service-response-time"#;
const TRACEROUTE_AFTER_HELP: &str = r#"Examples:
  packetcraftr traceroute 192.0.2.1 --strategy icmp
  packetcraftr --output ndjson traceroute example.test --allow-hostname-resolution"#;
const DNS_AFTER_HELP: &str = r#"Examples:
  packetcraftr dns 192.0.2.53 example.test --type a
  packetcraftr --output json dns 192.0.2.53 _service._tcp.example.test --type srv"#;
const FUZZ_AFTER_HELP: &str = r#"Examples:
  packetcraftr fuzz --packet 'ipv4(dst=192.0.2.1)/udp(dport=9)/raw(text=hi)' --cases 16
  packetcraftr fuzz --packet-file packet.json --seed 7 --first-case 42 --cases 1"#;
const ROUTES_AFTER_HELP: &str = r#"Examples:
  packetcraftr routes
  packetcraftr --output json routes"#;

#[derive(Debug, Parser)]
#[command(
    name = "packetcraftr",
    bin_name = "packetcraftr",
    version,
    arg_required_else_help = true,
    about = "Reflective packet construction, dissection, capture, and network tools",
    long_about = "PacketcraftR builds and dissects arbitrary packet stacks with exact bytes, bounded parsing, passive route planning, and policy-gated live workflows. Native features, dependencies, and privileges determine which live paths are available.",
    after_long_help = ROOT_AFTER_HELP
)]
pub(crate) struct Cli {
    /// Select the output encoding; supported formats are command-specific.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "FORMAT",
        help_heading = "Global options",
        default_value_t = CliOutputFormat::Text
    )]
    pub(crate) output: CliOutputFormat,
    /// Control terminal colours in human-facing output.
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "WHEN",
        help_heading = "Global options",
        default_value_t = CliColorChoice::Auto
    )]
    pub(crate) color: CliColorChoice,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliOutputFormat {
    #[default]
    Text,
    Json,
    Ndjson,
    Hex,
    Raw,
    Pcap,
    Pcapng,
}

impl std::fmt::Display for CliOutputFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(output::contract::Format::from(*self).as_str())
    }
}

impl From<CliOutputFormat> for output::contract::Format {
    fn from(value: CliOutputFormat) -> Self {
        match value {
            CliOutputFormat::Text => Self::Text,
            CliOutputFormat::Json => Self::Json,
            CliOutputFormat::Ndjson => Self::Ndjson,
            CliOutputFormat::Hex => Self::Hex,
            CliOutputFormat::Raw => Self::Raw,
            CliOutputFormat::Pcap => Self::Pcap,
            CliOutputFormat::Pcapng => Self::Pcapng,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliColorChoice {
    /// Use colour only when the destination supports it.
    #[default]
    Auto,
    /// Always emit colour for human-facing output.
    Always,
    /// Never emit colour.
    Never,
}

impl std::fmt::Display for CliColorChoice {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        })
    }
}

impl CliColorChoice {
    pub(crate) fn write_global(self) {
        let choice = match self {
            Self::Auto => anstream::ColorChoice::Auto,
            Self::Always => anstream::ColorChoice::Always,
            Self::Never => anstream::ColorChoice::Never,
        };
        choice.write_global();
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, CliColorChoice, Command};

    #[test]
    fn packet_sources_are_mutually_exclusive() {
        let result = Cli::try_parse_from([
            "packetcraftr",
            "build",
            "--packet",
            "raw()",
            "--packet-file",
            "packet.json",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn protocols_cli_parses_an_optional_protocol_name() {
        let list = Cli::try_parse_from(["packetcraftr", "protocols"]).unwrap();
        let Command::Protocols(arguments) = list.command else {
            panic!("expected protocols command");
        };
        assert_eq!(arguments.protocol, None);

        let detail = Cli::try_parse_from(["packetcraftr", "protocols", "IP4"]).unwrap();
        let Command::Protocols(arguments) = detail.command else {
            panic!("expected protocols command");
        };
        assert_eq!(arguments.protocol.as_deref(), Some("IP4"));
    }

    #[test]
    fn capture_parses_native_and_display_filters_independently() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "capture",
            "--packet",
            "ipv4(dst=192.0.2.53)/udp(dport=53)",
            "--capture-filter",
            "udp port 53",
            "--filter",
            "udp.source_port == 53",
        ])
        .unwrap();
        let Command::Capture(arguments) = cli.command else {
            panic!("expected capture command");
        };
        assert_eq!(arguments.capture_filter.as_deref(), Some("udp port 53"));
        assert_eq!(arguments.filter.as_deref(), Some("udp.source_port == 53"));
    }

    #[test]
    fn global_colour_choice_parses_before_or_after_the_subcommand() {
        for arguments in [
            [
                "packetcraftr",
                "--color",
                "always",
                "build",
                "--packet",
                "raw()",
            ],
            [
                "packetcraftr",
                "build",
                "--packet",
                "raw()",
                "--color",
                "always",
            ],
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(cli.color, CliColorChoice::Always));
        }
    }

    #[test]
    fn help_uses_the_frozen_cross_platform_binary_name() {
        let error = Cli::try_parse_from(["packetcraftr.exe", "build", "--help"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("Usage: packetcraftr build [OPTIONS]"));
        assert!(!help.contains("packetcraftr.exe"));
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Build exact packet bytes from an expression or document.
    #[command(after_long_help = BUILD_AFTER_HELP)]
    Build(BuildArgs),
    /// Decode a frame with bounded, registry-driven dissection.
    #[command(after_long_help = DISSECT_AFTER_HELP)]
    Dissect(DissectArgs),
    /// List built-in protocols or describe one protocol.
    #[command(after_long_help = PROTOCOLS_AFTER_HELP)]
    Protocols(ProtocolsArgs),
    /// Stream frames from a classic PCAP or PCAPNG file.
    #[command(after_long_help = READ_AFTER_HELP)]
    Read(ReadArgs),
    /// Enumerate local interfaces.
    #[command(after_long_help = INTERFACES_AFTER_HELP)]
    Interfaces,
    /// Passively select route, source, MTU, and link mode.
    #[command(after_long_help = PLAN_AFTER_HELP)]
    Plan(RouteArgs),
    /// Transmit a packet under traffic policy.
    #[command(after_long_help = SEND_AFTER_HELP)]
    Send(SendArgs),
    /// Capture-ready request/response exchange.
    #[command(after_long_help = EXCHANGE_AFTER_HELP)]
    Exchange(ExchangeArgs),
    /// Stream live captured frames.
    #[command(after_long_help = CAPTURE_AFTER_HELP)]
    Capture(CaptureArgs),
    /// Report protocol health findings over a capture file.
    #[command(after_long_help = EXPERT_AFTER_HELP)]
    Expert(ExpertArgs),
    /// Extract one conversation's payload from a capture file.
    #[command(after_long_help = FOLLOW_AFTER_HELP)]
    Follow(FollowArgs),
    /// Replay a PCAP/PCAPNG stream.
    #[command(after_long_help = REPLAY_AFTER_HELP)]
    Replay(ReplayArgs),
    /// Run a structured network scan.
    #[command(after_long_help = SCAN_AFTER_HELP)]
    Scan(ScanArgs),
    /// Compute aggregate statistics over a capture file.
    #[command(after_long_help = STATS_AFTER_HELP)]
    Stats(StatsArgs),
    /// Run bounded, policy-gated traceroute probes.
    #[command(
        long_about = "Run bounded, policy-gated traceroute probes. UDP starts at --port and increments the destination port for every probe; TCP keeps --port fixed. Each hop sends its attempts as one burst and shares one --timeout-ms response window. Traceroute supports text, JSON, and NDJSON output. Public destinations and hostname resolution require their respective explicit policy options.",
        after_long_help = TRACEROUTE_AFTER_HELP
    )]
    Traceroute(TracerouteArgs),
    /// Run a structured DNS operation.
    #[command(after_long_help = DNS_AFTER_HELP)]
    Dns(DnsArgs),
    /// Run bounded field-aware packet fuzzing.
    #[command(after_long_help = FUZZ_AFTER_HELP)]
    Fuzz(FuzzArgs),
    /// Enumerate passive interface-bound route decisions.
    #[command(after_long_help = ROUTES_AFTER_HELP)]
    Routes,
}
