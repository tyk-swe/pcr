// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native-system composition used by CLI commands.
//!
//! This module binds the facade's provider traits to system route, neighbor,
//! capture, and transmission adapters. It does not own command dispatch or
//! output rendering.

mod client;
mod interface;
mod route;
mod target;

pub(crate) use interface::{DeferredInterface, validate_interface_selector};

pub(crate) use route::{prepare_route_request, workflow_exchange_options};

pub(crate) use client::{SystemClient, default_registry_arc, system_client};

pub(crate) use target::parse_workflow_target;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;
    use packetcraftr::{client, net, workflow};

    use super::{parse_workflow_target, validate_interface_selector, workflow_exchange_options};
    use crate::cli::Cli;

    #[test]
    fn scan_request_validation_fails_before_route_or_live_io() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "scan",
            "192.168.56.10",
            "--transport",
            "icmp",
            "--ports",
            "80",
        ])
        .unwrap();
        let error = cli.command.run(cli.output.into()).unwrap_err();
        assert_eq!(error.classification.code, "cli.scan_limit");
        assert!(error.message.contains("ICMP scans are portless"));
    }

    #[test]
    fn dns_request_validation_fails_before_route_or_live_io() {
        let cli =
            Cli::try_parse_from(["packetcraftr", "dns", "10.0.0.53", "bad name.example"]).unwrap();
        let error = cli.command.run(cli.output.into()).unwrap_err();
        assert_eq!(error.classification.code, "packet.dns_query");
        assert!(error.message.contains("invalid"));
    }

    #[test]
    fn traceroute_request_validation_fails_before_route_or_live_io() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "traceroute",
            "192.168.56.10",
            "--strategy",
            "icmp",
            "--port",
            "80",
        ])
        .unwrap();
        let error = cli.command.run(cli.output.into()).unwrap_err();
        assert_eq!(error.classification.code, "cli.traceroute_limit");
        assert!(error.message.contains("ICMP traceroute is portless"));
    }

    #[test]
    fn traceroute_rejects_zero_udp_and_tcp_ports_before_live_io() {
        for strategy in ["udp", "tcp"] {
            let cli = Cli::try_parse_from([
                "packetcraftr",
                "traceroute",
                "192.168.56.10",
                "--strategy",
                strategy,
                "--port",
                "0",
            ])
            .unwrap();
            let error = cli.command.run(cli.output.into()).unwrap_err();
            assert_eq!(error.classification.code, "cli.traceroute_limit");
            assert!(
                error
                    .message
                    .contains("UDP and TCP traceroute require a non-zero destination port")
            );
        }
    }

    #[test]
    fn traceroute_rejects_unsupported_output_before_request_validation_or_live_io() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "--output",
            "pcap",
            "traceroute",
            "not a valid target",
        ])
        .unwrap();
        let error = cli.command.run(cli.output.into()).unwrap_err();
        assert_eq!(error.classification.code, "cli.output_format");
    }

    #[test]
    fn decimal_interface_selectors_never_fall_back_to_names() {
        assert_eq!(
            validate_interface_selector("test", Some("7")).unwrap(),
            Some(7)
        );
        assert_eq!(
            validate_interface_selector("test", Some("eth0")).unwrap(),
            None
        );

        for selector in ["", "0", "4294967296", "999999999999999999999999"] {
            let error = validate_interface_selector("test", Some(selector)).unwrap_err();
            assert_eq!(error.exit_code, 2, "{selector:?}");
        }
    }

    #[test]
    fn workflow_target_parsing_uses_the_shared_client_target_grammar() {
        let address = parse_workflow_target("192.0.2.1".to_owned()).unwrap();
        assert!(matches!(
            address,
            workflow::target::Target::Address(std::net::IpAddr::V4(_))
        ));

        let hostname = parse_workflow_target("example.test".to_owned()).unwrap();
        assert_eq!(
            hostname,
            workflow::target::Target::Hostname("example.test".to_owned())
        );
        assert!(parse_workflow_target("invalid target".to_owned()).is_err());
    }

    #[test]
    fn workflow_exchange_options_share_capture_bounds_and_decode_limit() {
        let limits = net::capture::Limits::default();
        let timeout = Duration::from_millis(25);
        let options =
            workflow_exchange_options(client::send::Options::default(), timeout, 3, limits)
                .unwrap();

        assert_eq!(options.timeout, timeout);
        assert_eq!(options.max_template_packets, 3);
        assert_eq!(options.max_unsolicited, limits.max_frames);
        assert_eq!(options.max_responses, limits.max_frames);
        assert_eq!(options.max_capture_queue_frames, limits.max_frames);
        assert_eq!(options.max_captured_bytes, limits.max_bytes);
        assert_eq!(options.capture_overflow_policy, limits.overflow_policy);
        assert_eq!(options.decode.max_packet_size, limits.snap_length);
    }
}
