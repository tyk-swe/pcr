// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::engine::command::DnsTransportMode;
use clap::Parser;

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    PacketcraftArgs::command().debug_assert()
}

fn try_parse_send_from(args: &[&str]) -> std::result::Result<PacketcraftArgs, clap::Error> {
    let mut full_args = vec!["packetcraftr", "send"];
    full_args.extend_from_slice(args);
    PacketcraftArgs::try_parse_from(full_args)
}

fn parse_send_from(args: &[&str]) -> PacketcraftArgs {
    try_parse_send_from(args).expect("send command should parse")
}

fn send_options(args: &PacketcraftArgs) -> &OneShotOptions {
    args.one_shot_options().expect("send options should exist")
}

#[test]
fn safety_options_are_parsed_and_mapped_to_engine_config() {
    let args = parse_send_from(&[
        "--allow-public-targets",
        "--allow-malformed",
        "--allow-high-volume",
        "--traffic-max-targets",
        "300",
        "--traffic-max-ports",
        "1200",
        "--traffic-max-packets",
        "5000",
        "--traffic-batch-size",
        "300",
        "--traffic-rate",
        "200",
    ]);

    assert!(args.safety.allow_public_targets);
    assert!(args.safety.allow_malformed);
    assert!(args.safety.allow_high_volume);

    let config = args.engine_config();
    assert!(config.traffic_policy.allow_public_targets);
    assert!(config.traffic_policy.allow_malformed);
    assert!(config.traffic_policy.allow_high_volume);
    assert_eq!(config.traffic_policy.budget.max_targets, 300);
    assert_eq!(config.traffic_policy.budget.max_ports, 1200);
    assert_eq!(config.traffic_policy.budget.max_estimated_packets, 5000);
    assert_eq!(config.traffic_policy.budget.max_batch_size, 300);
    assert_eq!(config.traffic_policy.budget.max_rate_per_sec, 200);
}

#[test]
fn conflicting_transport_layers_are_rejected() {
    let result = try_parse_send_from(&["tcp", "udp"]);
    assert!(result.is_err());
    let result = try_parse_send_from(&["tcp", "icmp"]);
    assert!(result.is_err());
    let result = try_parse_send_from(&["udp", "icmp"]);
    assert!(result.is_err());
    let result = try_parse_send_from(&["tcp", "udp", "icmp"]);
    assert!(result.is_err());
}

#[test]
fn command_is_required() {
    let result = PacketcraftArgs::try_parse_from(["packetcraftr"]);
    assert!(result.is_err());
}

#[cfg(feature = "pcap")]
#[test]
fn listen_subcommand_parses_timeout() {
    let args = PacketcraftArgs::try_parse_from([
        "packetcraftr",
        "listen",
        "--timeout",
        "5",
        "--persistent",
    ])
    .expect("listen command should parse");

    match args.command {
        PacketcraftCommand::Listen(options) => {
            assert_eq!(options.listen.timeout, Some(5));
            assert_eq!(options.persistent, Some(true));
        }
        other => panic!("expected listen command, got {other:?}"),
    }
}

#[test]
fn invalid_fragment_profile_is_rejected() {
    let result = try_parse_send_from(&["--frag-profile", "invalid"]);
    assert!(result.is_err());
}

#[test]
fn invalid_mac_address_is_rejected() {
    let result = try_parse_send_from(&["--smac", "invalid"]);
    assert!(result.is_err());
    let result = try_parse_send_from(&["--dmac", "invalid"]);
    assert!(result.is_err());
}

#[test]
fn valid_mac_addresses_are_accepted() {
    let args = parse_send_from(&["--smac", "aa:bb:cc:dd:ee:ff", "--dmac", "11:22:33:44:55:66"]);

    assert_eq!(
        send_options(&args).layer2.source_mac.as_deref(),
        Some("aa:bb:cc:dd:ee:ff")
    );
    assert_eq!(
        send_options(&args).layer2.destination_mac.as_deref(),
        Some("11:22:33:44:55:66")
    );
}

#[test]
fn invalid_socket_address_is_rejected() {
    let result = try_parse_send_from(&["--prometheus-bind", "invalid"]);
    assert!(result.is_err());
    let result = try_parse_send_from(&["--prometheus-bind", "127.0.0.1"]); // missing port
    assert!(result.is_err());
}

#[test]
fn valid_socket_address_is_accepted() {
    let args = parse_send_from(&["--prometheus-bind", "127.0.0.1:9898"]);

    assert_eq!(
        send_options(&args).logging.prometheus_bind.as_deref(),
        Some("127.0.0.1:9898")
    );
}

#[test]
fn logging_options_accept_structured_mode() {
    let args = parse_send_from(&[
        "--log-level",
        "debug",
        "--log-structured",
        "--metrics-json",
        "out.json",
    ]);

    assert_eq!(send_options(&args).logging.log_level, Some(LogLevel::Debug));
    assert_eq!(send_options(&args).logging.structured, Some(true));
    assert_eq!(
        send_options(&args).logging.metrics_json.as_deref(),
        Some("out.json")
    );
}

#[cfg(feature = "scan")]
#[derive(Clone, Copy)]
struct PortScanCase {
    subcommand: &'static str,
    target: &'static str,
    ports: &'static str,
    interface: Option<&'static str>,
    source_ip: Option<&'static str>,
}

#[cfg(feature = "scan")]
#[derive(Clone, Copy)]
struct TimedScanCase {
    subcommand: &'static str,
    target: &'static str,
    timeout: u64,
    interface: Option<&'static str>,
    source_ip: Option<&'static str>,
}

#[cfg(feature = "scan")]
fn parse_scan_from(args: &[&str]) -> ScanCommand {
    let mut full_args = vec!["packetcraftr", "scan"];
    full_args.extend_from_slice(args);

    match PacketcraftArgs::try_parse_from(full_args)
        .expect("scan command should parse")
        .command
    {
        PacketcraftCommand::Scan(command) => command,
        other => panic!("expected scan command, got {other:?}"),
    }
}

#[cfg(feature = "scan")]
fn parse_port_scan(case: PortScanCase) -> ScanCommand {
    let mut args = vec![
        case.subcommand,
        "--target",
        case.target,
        "--ports",
        case.ports,
    ];
    if let Some(interface) = case.interface {
        args.extend(["--interface", interface]);
    }
    if let Some(source_ip) = case.source_ip {
        args.extend(["--source-ip", source_ip]);
    }
    parse_scan_from(&args)
}

#[cfg(feature = "scan")]
fn parse_timed_scan(case: TimedScanCase) -> ScanCommand {
    let timeout = case.timeout.to_string();
    let mut args = vec![
        case.subcommand,
        "--target",
        case.target,
        "--timeout",
        timeout.as_str(),
    ];
    if let Some(interface) = case.interface {
        args.extend(["--interface", interface]);
    }
    if let Some(source_ip) = case.source_ip {
        args.extend(["--source-ip", source_ip]);
    }
    parse_scan_from(&args)
}

#[cfg(feature = "scan")]
fn assert_port_scan(command: ScanCommand, case: PortScanCase) {
    let options = match (case.subcommand, command) {
        ("tcp-syn", ScanCommand::TcpSyn(options)) => options,
        ("tcp-fin", ScanCommand::TcpFin(options)) => options,
        ("tcp-null", ScanCommand::TcpNull(options)) => options,
        ("tcp-xmas", ScanCommand::TcpXmas(options)) => options,
        ("tcp-ack", ScanCommand::TcpAck(options)) => options,
        ("sctp-init", ScanCommand::SctpInit(options)) => options,
        ("udp", ScanCommand::Udp(options)) => options,
        (expected, other) => panic!("expected {expected} variant, got {other:?}"),
    };

    assert_eq!(options.target, case.target);
    assert_eq!(options.ports, case.ports);
    assert_eq!(options.interface.as_deref(), case.interface);
    assert_eq!(options.source_ip.as_deref(), case.source_ip);
}

#[cfg(feature = "scan")]
fn assert_timed_scan(command: ScanCommand, case: TimedScanCase) {
    let options = match (case.subcommand, command) {
        ("arp", ScanCommand::Arp(options)) => options,
        ("ndp", ScanCommand::Ndp(options)) => options,
        ("icmp", ScanCommand::Icmp(options)) => options,
        (expected, other) => panic!("expected {expected} variant, got {other:?}"),
    };

    assert_eq!(options.target, case.target);
    assert_eq!(options.timeout, case.timeout);
    assert_eq!(options.interface.as_deref(), case.interface);
    assert_eq!(options.source_ip.as_deref(), case.source_ip);
}

#[cfg(feature = "scan")]
#[test]
fn scan_command_parses_port_variants() {
    for case in [
        PortScanCase {
            subcommand: "tcp-syn",
            target: "192.0.2.1",
            ports: "80,443",
            interface: None,
            source_ip: None,
        },
        PortScanCase {
            subcommand: "tcp-fin",
            target: "192.0.2.1",
            ports: "80,443",
            interface: None,
            source_ip: None,
        },
        PortScanCase {
            subcommand: "tcp-null",
            target: "192.0.2.1",
            ports: "80,443",
            interface: None,
            source_ip: None,
        },
        PortScanCase {
            subcommand: "tcp-xmas",
            target: "192.0.2.1",
            ports: "80,443",
            interface: None,
            source_ip: None,
        },
        PortScanCase {
            subcommand: "tcp-ack",
            target: "192.0.2.1",
            ports: "80,443",
            interface: None,
            source_ip: None,
        },
        PortScanCase {
            subcommand: "sctp-init",
            target: "192.0.2.1",
            ports: "80,443",
            interface: None,
            source_ip: None,
        },
        PortScanCase {
            subcommand: "udp",
            target: "192.0.2.0/24",
            ports: "53",
            interface: None,
            source_ip: Some("192.0.2.10"),
        },
    ] {
        assert_port_scan(parse_port_scan(case), case);
    }
}

#[cfg(feature = "scan")]
#[test]
fn scan_command_parses_timed_variants() {
    for case in [
        TimedScanCase {
            subcommand: "arp",
            target: "192.0.2.0/30",
            timeout: 250,
            interface: None,
            source_ip: None,
        },
        TimedScanCase {
            subcommand: "ndp",
            target: "2001:db8::/64",
            timeout: 500,
            interface: None,
            source_ip: None,
        },
        TimedScanCase {
            subcommand: "icmp",
            target: "192.168.1.0/24",
            timeout: 500,
            interface: Some("eth0"),
            source_ip: None,
        },
    ] {
        assert_timed_scan(parse_timed_scan(case), case);
    }
}

#[test]
fn vlan_options_are_parsed_correctly() {
    let args = parse_send_from(&["--vlan-id", "100", "--vlan-prio", "5", "--vlan-dei"]);

    assert_eq!(send_options(&args).layer2.vlan.id, Some(100));
    assert_eq!(send_options(&args).layer2.vlan.priority, Some(5));
    assert_eq!(
        send_options(&args).layer2.vlan.drop_eligible_indicator,
        Some(true)
    );
}

#[test]
fn vlan_id_out_of_range_is_rejected() {
    let result_too_low = try_parse_send_from(&["--vlan-id", "0"]);
    assert!(result_too_low.is_err());

    let result_too_high = try_parse_send_from(&["--vlan-id", "4095"]);
    assert!(result_too_high.is_err());
}

#[test]
fn vlan_prio_out_of_range_is_rejected() {
    let result = try_parse_send_from(&["--vlan-prio", "8"]);
    assert!(result.is_err());
}

#[test]
fn ip_options_conflicting_prefer_flags_are_rejected() {
    let result = try_parse_send_from(&["--prefer-ipv4", "--prefer-ipv6"]);
    assert!(result.is_err());
}

#[test]
fn ip_options_conflicting_fragmentation_flags_are_rejected() {
    let result_df_mf = try_parse_send_from(&["--df-flag", "--mf-flag"]);
    assert!(result_df_mf.is_err());

    let result_overlap_teardrop = try_parse_send_from(&["--frag-overlap", "--teardrop"]);
    assert!(result_overlap_teardrop.is_err());

    let result_profile_overlap =
        try_parse_send_from(&["--frag-profile", "overlap", "--frag-overlap"]);
    assert!(result_profile_overlap.is_err());
}

#[test]
fn tcp_options_are_parsed_correctly() {
    let args = parse_send_from(&[
        "tcp",
        "--flags",
        "SA",
        "--seq",
        "123",
        "--ack",
        "456",
        "--window",
        "1024",
        "--tcp-mss",
        "1460",
    ]);

    match send_options(&args).transport.command.clone() {
        Some(TransportCommand::Tcp(opts)) => {
            assert_eq!(opts.flags.as_deref(), Some("SA"));
            assert_eq!(opts.sequence, Some(123));
            assert_eq!(opts.acknowledgement, Some(456));
            assert_eq!(opts.window_size, Some(1024));
            assert_eq!(opts.mss, Some(1460));
        }
        other => panic!("expected tcp subcommand, got {other:?}"),
    }
}

#[test]
fn icmpv6_options_error_kind_parses_correctly() {
    let args = parse_send_from(&["icmpv6", "--error", "destination-unreachable"]);

    match send_options(&args).transport.command.clone() {
        Some(TransportCommand::Icmpv6(opts)) => {
            assert_eq!(opts.error, Some(Icmpv6ErrorKind::DestinationUnreachable));
        }
        other => panic!("expected icmpv6 subcommand, got {other:?}"),
    }
}

#[test]
fn icmpv6_options_mtu_parameter_parses() {
    let args = parse_send_from(&["icmpv6", "--mtu", "1280"]);

    match send_options(&args).transport.command.clone() {
        Some(TransportCommand::Icmpv6(opts)) => {
            assert_eq!(opts.mtu, Some(1280));
        }
        other => panic!("expected icmpv6 subcommand, got {other:?}"),
    }
}

#[test]
fn icmp_options_parse_correctly() {
    let args = parse_send_from(&[
        "icmp",
        "--icmp-type",
        "8",
        "--icmp-code",
        "0",
        "--icmp-id",
        "1234",
        "--icmp-seq",
        "5678",
    ]);

    match send_options(&args).transport.command.clone() {
        Some(TransportCommand::Icmp(opts)) => {
            assert_eq!(opts.kind, Some(8));
            assert_eq!(opts.code, Some(0));
            assert_eq!(opts.identifier, Some(1234));
            assert_eq!(opts.sequence, Some(5678));
        }
        other => panic!("expected icmp subcommand, got {other:?}"),
    }
}

#[cfg(feature = "traceroute")]
#[test]
fn traceroute_options_parse_defaults() {
    let args =
        PacketcraftArgs::try_parse_from(["packetcraftr", "traceroute", "--dest", "example.com"])
            .expect("traceroute should parse with defaults");

    match args.command {
        PacketcraftCommand::Traceroute(opts) => {
            assert_eq!(opts.destination, "example.com");
            assert_eq!(opts.max_ttl, 30);
            assert_eq!(opts.probes, 3);
            assert!(matches!(opts.protocol, TracerouteProtocol::Udp));
        }
        other => panic!("expected traceroute command, got {other:?}"),
    }
}

#[cfg(feature = "traceroute")]
#[test]
fn traceroute_options_accepts_overrides() {
    let args = PacketcraftArgs::try_parse_from([
        "packetcraftr",
        "traceroute",
        "--dest",
        "203.0.113.7",
        "--max-ttl",
        "12",
        "--probes",
        "1",
        "--protocol",
        "tcp",
    ])
    .expect("traceroute overrides should parse");

    match args.command {
        PacketcraftCommand::Traceroute(opts) => {
            assert_eq!(opts.destination, "203.0.113.7");
            assert_eq!(opts.max_ttl, 12);
            assert_eq!(opts.probes, 1);
            assert!(matches!(opts.protocol, TracerouteProtocol::Tcp));
        }
        other => panic!("expected traceroute command, got {other:?}"),
    }
}

#[cfg(feature = "traceroute")]
#[test]
fn traceroute_protocol_parser_rejects_invalid_values() {
    let result = PacketcraftArgs::try_parse_from([
        "packetcraftr",
        "traceroute",
        "--dest",
        "198.51.100.9",
        "--protocol",
        "bogus",
    ]);

    assert!(result.is_err(), "invalid protocol should be rejected");
}

#[test]
fn payload_options_parse_all_variants() {
    let data_args = parse_send_from(&["--data", "hello world"]);
    assert_eq!(
        send_options(&data_args).payload.data.as_deref(),
        Some("hello world")
    );

    let hex_args = parse_send_from(&["--data-hex", "deadbeef"]);
    assert_eq!(
        send_options(&hex_args).payload.data_hex.as_deref(),
        Some("deadbeef")
    );

    let file_args = parse_send_from(&["--data-file", "/tmp/payload.bin"]);
    assert_eq!(
        send_options(&file_args).payload.data_file.as_deref(),
        Some("/tmp/payload.bin")
    );

    let random_args = parse_send_from(&["--rand-payload", "256"]);
    assert_eq!(
        send_options(&random_args).payload.random_payload_size,
        Some(256)
    );
}

#[test]
fn payload_options_parse_after_transport_subcommand() {
    let args = parse_send_from(&["udp", "--dport", "9", "--data", "hello"]);

    assert_eq!(send_options(&args).payload.data.as_deref(), Some("hello"));
    assert!(matches!(
        send_options(&args).transport.command,
        Some(TransportCommand::Udp(_))
    ));
}

#[test]
fn rule_options_are_parsed_correctly() {
    let args = parse_send_from(&[
        "--rule-workers",
        "10",
        "--rule-queue",
        "20",
        "--send-workers",
        "30",
        "--send-queue",
        "40",
    ]);

    let rules = &send_options(&args).rule;
    assert_eq!(rules.rule_workers, Some(10));
    assert_eq!(rules.rule_queue, Some(20));
    assert_eq!(rules.send_workers, Some(30));
    assert_eq!(rules.send_queue, Some(40));
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_rule_options_are_parsed_correctly() {
    let args = PacketcraftArgs::try_parse_from(["packetcraftr", "daemon", "--rule-workers", "10"])
        .expect("daemon rule options should parse");

    match args.command {
        PacketcraftCommand::Daemon(opts) => {
            assert_eq!(opts.rule_options.rule_workers, Some(10));
        }
        _ => panic!("expected daemon command"),
    }
}

#[test]
fn dns_query_options_parse_correctly() {
    let args = PacketcraftArgs::try_parse_from([
        "packetcraftr",
        "dns-query",
        "--domain",
        "example.com",
        "--type",
        "AAAA",
        "--server",
        "1.1.1.1",
        "--timeout",
        "500",
        "--transport",
        "tcp",
        "--retries",
        "3",
    ])
    .expect("dns-query options should parse");

    match args.command {
        PacketcraftCommand::DnsQuery(opts) => {
            assert_eq!(opts.domain, "example.com");
            assert_eq!(opts.record_type, "AAAA");
            assert_eq!(opts.server, "1.1.1.1");
            assert_eq!(opts.timeout, 500);
            assert_eq!(opts.transport, DnsTransportMode::Tcp);
            assert_eq!(opts.retries, 3);
        }
        other => panic!("expected dns-query command, got {other:?}"),
    }
}

#[test]
fn dns_query_options_default_transport_and_retries() {
    let args =
        PacketcraftArgs::try_parse_from(["packetcraftr", "dns-query", "--domain", "example.com"])
            .expect("dns-query options should parse");

    match args.command {
        PacketcraftCommand::DnsQuery(opts) => {
            assert_eq!(opts.transport, DnsTransportMode::Auto);
            assert_eq!(opts.retries, 0);
        }
        other => panic!("expected dns-query command, got {other:?}"),
    }
}

#[test]
fn dns_query_rejects_out_of_range_retries() {
    let result = PacketcraftArgs::try_parse_from([
        "packetcraftr",
        "dns-query",
        "--domain",
        "example.com",
        "--retries",
        "6",
    ]);

    assert!(result.is_err());
}

#[test]
fn dry_run_flag_parses_at_top_level() {
    let args = PacketcraftArgs::try_parse_from([
        "packetcraftr",
        "--dry-run",
        "send",
        "-d",
        "127.0.0.1",
        "udp",
    ])
    .expect("dry-run flag should parse");
    assert!(args.dry_run);
    assert!(args.effective_dry_run());
}

#[test]
fn send_command_accepts_dry_run_flag_after_subcommand() {
    let args = PacketcraftArgs::try_parse_from([
        "packetcraftr",
        "send",
        "--dry-run",
        "-d",
        "127.0.0.1",
        "udp",
    ])
    .expect("send --dry-run should parse");
    assert!(args.dry_run);
    assert!(matches!(args.command, PacketcraftCommand::Send(_)));
}

#[test]
fn dry_run_command_forces_effective_dry_run() {
    let args =
        PacketcraftArgs::try_parse_from(["packetcraftr", "dry-run", "-d", "127.0.0.1", "udp"])
            .expect("dry-run command should parse");
    assert!(!args.dry_run);
    assert!(args.effective_dry_run());
    assert!(matches!(args.command, PacketcraftCommand::DryRun(_)));
}

#[test]
fn optional_bool_flags_do_not_consume_transport_subcommands() {
    let args = PacketcraftArgs::try_parse_from([
        "packetcraftr",
        "dry-run",
        "-d",
        "127.0.0.1",
        "--flood",
        "udp",
        "--dport",
        "9",
    ])
    .expect("bare --flood should not consume udp as a boolean value");

    match args.command {
        PacketcraftCommand::DryRun(options) => {
            assert_eq!(options.oneshot.transmit.flood, Some(true));
            assert!(matches!(
                options.oneshot.transport.command,
                Some(TransportCommand::Udp(_))
            ));
        }
        other => panic!("expected dry-run command, got {other:?}"),
    }
}

#[test]
fn dry_run_flag_parses_on_subcommand() {
    let args = PacketcraftArgs::try_parse_from([
        "packetcraftr",
        "dns-query",
        "--domain",
        "example.com",
        "--dry-run",
    ])
    .expect("dry-run flag on subcommand should parse");
    assert!(args.dry_run);
}

#[cfg(not(feature = "pcap"))]
#[test]
fn listen_command_is_hidden_without_pcap_feature() {
    let result = PacketcraftArgs::try_parse_from(["packetcraftr", "listen", "--timeout", "5"]);
    assert!(result.is_err());
}

#[cfg(not(feature = "scan"))]
#[test]
fn scan_command_is_hidden_without_scan_feature() {
    let result = PacketcraftArgs::try_parse_from([
        "packetcraftr",
        "scan",
        "tcp-syn",
        "--target",
        "127.0.0.1",
    ]);
    assert!(result.is_err());
}

#[cfg(not(feature = "traceroute"))]
#[test]
fn traceroute_command_is_hidden_without_traceroute_feature() {
    let result = PacketcraftArgs::try_parse_from(["packetcraftr", "traceroute", "--dest", "::1"]);
    assert!(result.is_err());
}

#[cfg(not(feature = "daemon"))]
#[test]
fn daemon_command_is_hidden_without_daemon_feature() {
    let result = PacketcraftArgs::try_parse_from(["packetcraftr", "daemon", "--foreground"]);
    assert!(result.is_err());
}

#[cfg(not(feature = "fuzz"))]
#[test]
fn fuzz_command_is_hidden_without_fuzz_feature() {
    let result = PacketcraftArgs::try_parse_from([
        "packetcraftr",
        "fuzz",
        "--target",
        "127.0.0.1",
        "--protocol",
        "udp",
    ]);
    assert!(result.is_err());
}

#[cfg(not(feature = "repl"))]
#[test]
fn interactive_command_is_hidden_without_repl_feature() {
    let result = PacketcraftArgs::try_parse_from(["packetcraftr", "interactive"]);
    assert!(result.is_err());
}
