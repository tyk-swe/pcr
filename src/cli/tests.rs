// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Binary CLI unit tests.

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

use clap::Parser;
use packetcraftr::{
    capture::{self, Format, Frame, LinkType, Reader, Writer},
    client, net, output, workflow,
};

use super::arguments::{
    Cli, CliAddressFamily, CliDnsQueryType, CliLinkMode, CliScanTransport, CliTracerouteStrategy,
    Command,
};
use super::commands::{
    CaptureBudget, dns_cli_error, drive_capture, fuzz_cli_error, replay_cli_error, scan_cli_error,
    send_capture_link_type, traceroute_cli_error, write_replay_capture_evidence,
};
use super::errors::CliError;
use super::input::read_bounded_allow_empty;
use super::rendering::{encode_capture_file, output_timestamp_text, terminal_safe};
use super::runtime::{
    parse_workflow_target, run, validate_interface_selector, workflow_exchange_options,
};

struct ScriptedCapture {
    ready: Option<Result<(), net::Error>>,
    frames: VecDeque<Result<Option<Frame>, net::Error>>,
    shutdown: Option<Result<(), net::Error>>,
    statistics: net::capture::Statistics,
}

impl net::capture::Session for ScriptedCapture {
    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), net::Error> {
        self.ready.take().unwrap_or(Ok(()))
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, net::Error> {
        self.frames.pop_front().unwrap_or(Ok(None))
    }

    fn shutdown(&mut self) -> Result<(), net::Error> {
        self.shutdown.take().unwrap_or(Ok(()))
    }

    fn statistics(&self) -> net::capture::Statistics {
        self.statistics
    }
}

fn test_capture_budget() -> CaptureBudget {
    CaptureBudget {
        max_frames: 10,
        max_bytes: 1024,
    }
}

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
fn help_uses_the_frozen_cross_platform_binary_name() {
    let error = Cli::try_parse_from(["packetcraftr.exe", "build", "--help"]).unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    let help = error.to_string();
    assert!(help.contains("Usage: packetcraftr build [OPTIONS]"));
    assert!(!help.contains("packetcraftr.exe"));
}

#[test]
fn scan_cli_parses_typed_transport_ports_and_finite_limits() {
    let cli = Cli::try_parse_from([
        "packetcraftr",
        "scan",
        "192.168.56.10",
        "--transport",
        "udp",
        "--ports",
        "53,161",
        "--attempts",
        "2",
        "--batch-size",
        "2",
        "--rate",
        "10",
    ])
    .unwrap();
    let Command::Scan(arguments) = cli.command else {
        panic!("expected scan command");
    };
    assert!(matches!(arguments.transport, CliScanTransport::Udp));
    assert_eq!(arguments.ports, [53, 161]);
    assert_eq!(arguments.attempts, 2);
    assert_eq!(arguments.batch_size, 2);
    assert_eq!(arguments.rate, Some(10));
}

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
    let error = run(cli).unwrap_err();
    assert_eq!(error.classification.code, "cli.scan_limit");
    assert!(error.message.contains("ICMP scans are portless"));
}

#[test]
fn dns_cli_parses_query_policy_route_and_finite_bounds() {
    let cli = Cli::try_parse_from([
        "packetcraftr",
        "dns",
        "10.0.0.53",
        "_service._tcp.example.test",
        "--type",
        "srv",
        "--family",
        "ipv4",
        "--port",
        "5353",
        "--transaction-id",
        "7",
        "--source-port",
        "50000",
        "--attempts",
        "3",
        "--rate",
        "10",
        "--interface",
        "test0",
        "--source",
        "10.0.0.2",
        "--link-mode",
        "layer3",
    ])
    .unwrap();
    let Command::Dns(arguments) = cli.command else {
        panic!("expected DNS command");
    };
    assert!(matches!(arguments.query_type, CliDnsQueryType::Srv));
    assert!(matches!(arguments.family, CliAddressFamily::Ipv4));
    assert_eq!(arguments.port, 5353);
    assert_eq!(arguments.transaction_id, Some(7));
    assert_eq!(arguments.source_port, Some(50_000));
    assert_eq!(arguments.attempts, 3);
    assert_eq!(arguments.rate, Some(10));
    assert_eq!(arguments.interface.as_deref(), Some("test0"));
    assert_eq!(arguments.source, Some("10.0.0.2".parse().unwrap()));
    assert!(matches!(arguments.link_mode, CliLinkMode::Layer3));
}

#[test]
fn dns_request_validation_fails_before_route_or_live_io() {
    let cli =
        Cli::try_parse_from(["packetcraftr", "dns", "10.0.0.53", "bad name.example"]).unwrap();
    let error = run(cli).unwrap_err();
    assert_eq!(error.classification.code, "packet.dns_query");
    assert!(error.message.contains("invalid"));
}

#[test]
fn traceroute_cli_parses_strategy_family_hops_attempts_and_rate() {
    let cli = Cli::try_parse_from([
        "packetcraftr",
        "traceroute",
        "192.168.56.10",
        "--strategy",
        "tcp",
        "--family",
        "ipv4",
        "--port",
        "443",
        "--first-hop",
        "2",
        "--max-hops",
        "12",
        "--attempts",
        "4",
        "--rate",
        "20",
    ])
    .unwrap();
    let Command::Traceroute(arguments) = cli.command else {
        panic!("expected traceroute command");
    };
    assert!(matches!(arguments.strategy, CliTracerouteStrategy::Tcp));
    assert!(matches!(arguments.family, CliAddressFamily::Ipv4));
    assert_eq!(arguments.port, Some(443));
    assert_eq!(arguments.first_hop, 2);
    assert_eq!(arguments.max_hops, 12);
    assert_eq!(arguments.attempts, 4);
    assert_eq!(arguments.rate, Some(20));
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
    let error = run(cli).unwrap_err();
    assert_eq!(error.classification.code, "cli.traceroute_limit");
    assert!(error.message.contains("ICMP traceroute is portless"));
}

#[test]
fn whole_frame_hex_is_not_truncated() {
    let bytes = (0u8..=255).collect::<Vec<_>>();
    assert_eq!(output::frame::Wire::new(bytes).bytes_hex.len(), 512);
}

#[test]
fn terminal_text_escapes_controls_and_directional_overrides() {
    let safe = terminal_safe("line\n\u{1b}[31m\u{2028}next\u{2029}\u{202e}tail");
    assert_eq!(
        safe,
        "line\\n\\u{1b}[31m\\u{2028}next\\u{2029}\\u{202e}tail"
    );
    assert!(!safe.chars().any(char::is_control));
    assert!(!safe.contains(['\u{2028}', '\u{2029}']));
}

#[test]
fn bounded_input_rejects_an_unrepresentable_sentinel_limit() {
    let error =
        read_bounded_allow_empty(std::io::Cursor::new(Vec::<u8>::new()), usize::MAX).unwrap_err();
    assert_eq!(error.exit_code, 70);
    assert!(error.message.contains("cannot be represented"));
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
fn pre_epoch_timestamp_text_uses_conventional_signed_decimal_notation() {
    assert_eq!(
        output_timestamp_text(output::frame::Timestamp {
            unix_seconds: -3,
            nanoseconds: 750_000_000,
        }),
        "-2.250000000"
    );
    assert_eq!(
        output_timestamp_text(output::frame::Timestamp {
            unix_seconds: -1,
            nanoseconds: 500_000_000,
        }),
        "-0.500000000"
    );
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
        workflow_exchange_options(client::send::Options::default(), timeout, 3, limits).unwrap();

    assert_eq!(options.timeout, timeout);
    assert_eq!(options.max_template_packets, 3);
    assert_eq!(options.max_unsolicited, limits.max_frames);
    assert_eq!(options.max_responses, limits.max_frames);
    assert_eq!(options.max_capture_queue_frames, limits.max_frames);
    assert_eq!(options.max_captured_bytes, limits.max_bytes);
    assert_eq!(options.capture_overflow_policy, limits.overflow_policy);
    assert_eq!(options.decode.max_packet_size, limits.snap_length);
}

#[test]
fn cli_errors_preserve_classification_when_crossing_a_workflow_boundary() {
    let classification = packetcraftr::error::Classification::new(
        "io.test_boundary",
        packetcraftr::error::Kind::Io,
        None,
    );
    let boundary = CliError::from_classification(
        classification,
        "boundary failed",
        vec!["underlying failure".to_owned()],
    )
    .into_boundary_error();

    assert_eq!(boundary.to_string(), "boundary failed");
    assert_eq!(
        packetcraftr::error::Classified::classification(&boundary),
        classification
    );
    assert_eq!(
        packetcraftr::error::Classified::causes(&boundary),
        ["underlying failure"]
    );
}

#[test]
fn per_item_tool_errors_retain_their_input_sequence() {
    let scan = scan_cli_error(workflow::scan::Error::InvalidEvidence {
        sequence: 7,
        message: "invalid scan evidence".to_owned(),
    });
    assert_eq!(scan.sequence, Some(7));

    let traceroute = traceroute_cli_error(workflow::traceroute::Error::InvalidEvidence {
        sequence: 8,
        message: "invalid traceroute evidence".to_owned(),
    });
    assert_eq!(traceroute.sequence, Some(8));

    let dns = dns_cli_error(workflow::dns::Error::InvalidEvidence {
        attempt: 3,
        message: "invalid DNS evidence".to_owned(),
    });
    assert_eq!(dns.sequence, Some(2));

    let fuzz = fuzz_cli_error(workflow::fuzz::Error::InvalidEvidence {
        case_index: 9,
        message: "invalid fuzz evidence".to_owned(),
    });
    assert_eq!(fuzz.sequence, Some(9));

    let replay = replay_cli_error(workflow::replay::Error::output(10, "replay output failed"));
    assert_eq!(replay.sequence, Some(10));
}

#[test]
fn classified_live_errors_use_the_frozen_cli_exit_contract() {
    let capability = CliError::classified(net::Error::Privilege {
        message: "permission denied".to_owned(),
    });
    assert_eq!(capability.exit_code, 4);
    assert_eq!(capability.classification.code, "capability.privilege");

    let runtime = CliError::classified(net::Error::PartialSend {
        expected: 10,
        actual: 9,
    });
    assert_eq!(runtime.exit_code, 5);
    assert_eq!(runtime.classification.code, "io.partial_send");

    let dual = CliError::classified(client::Error::OperationAndCaptureShutdown {
        operation: net::Error::Send {
            message: "send failed".to_owned(),
        },
        shutdown: net::Error::Capture {
            message: "join failed".to_owned(),
        },
    });
    assert_eq!(dual.causes.len(), 2);
    let envelope = output::envelope::AggregateError::error(
        Some(output::contract::Command::Exchange),
        dual.output_error(),
    );
    let envelope = serde_json::to_value(envelope).unwrap();
    assert_eq!(envelope["error"]["causes"].as_array().unwrap().len(), 2);
}

#[test]
fn capture_driver_streams_bounded_frames_and_reports_statistics() {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![1, 2, 3]).unwrap();
    let capture = ScriptedCapture {
        ready: Some(Ok(())),
        frames: VecDeque::from([Ok(Some(frame)), Ok(None)]),
        shutdown: Some(Ok(())),
        statistics: net::capture::Statistics {
            received_frames: 1,
            received_bytes: 3,
            ..net::capture::Statistics::default()
        },
    };
    let mut rendered = Vec::new();
    let outcome = drive_capture(
        capture,
        Duration::from_millis(10),
        net::capture::Limits::default(),
        test_capture_budget(),
        |frame, sequence| {
            rendered.push((sequence, frame.bytes().to_vec()));
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(rendered, vec![(0, vec![1, 2, 3])]);
    assert_eq!(outcome.stats.packets_completed, 1);
    assert_eq!(outcome.stats.bytes, 3);
    assert_eq!(outcome.stats.capture.received_frames, 1);
}

#[test]
fn zero_capture_window_is_a_clean_empty_timeout() {
    let capture = ScriptedCapture {
        ready: Some(Err(net::Error::CaptureReadiness {
            message: "zero window must not wait for readiness".to_owned(),
        })),
        frames: VecDeque::from([Err(net::Error::Capture {
            message: "must not be observed".to_owned(),
        })]),
        shutdown: Some(Ok(())),
        statistics: net::capture::Statistics::default(),
    };
    let outcome = drive_capture(
        capture,
        Duration::ZERO,
        net::capture::Limits::default(),
        test_capture_budget(),
        |_, _| unreachable!(),
    )
    .unwrap();
    assert_eq!(outcome.stats.packets_completed, 0);
}

#[test]
fn readiness_and_cleanup_failures_remain_structured() {
    let capture = ScriptedCapture {
        ready: Some(Err(net::Error::Privilege {
            message: "capture permission denied".to_owned(),
        })),
        frames: VecDeque::new(),
        shutdown: Some(Err(net::Error::Capture {
            message: "capture worker did not join".to_owned(),
        })),
        statistics: net::capture::Statistics::default(),
    };
    let error = drive_capture(
        capture,
        Duration::from_millis(10),
        net::capture::Limits::default(),
        test_capture_budget(),
        |_, _| Ok(()),
    )
    .unwrap_err();

    assert_eq!(error.exit_code, 4);
    assert_eq!(error.classification.code, "capability.privilege");
    assert_eq!(error.sequence, Some(0));
    assert_eq!(error.causes.len(), 2);
    assert!(error.causes[1].contains("did not join"));
}

#[test]
fn capture_byte_budget_fails_before_emitting_the_excess_frame() {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![1, 2, 3]).unwrap();
    let capture = ScriptedCapture {
        ready: Some(Ok(())),
        frames: VecDeque::from([Ok(Some(frame))]),
        shutdown: Some(Ok(())),
        statistics: net::capture::Statistics {
            received_frames: 1,
            received_bytes: 3,
            ..net::capture::Statistics::default()
        },
    };
    let mut emitted = false;
    let error = drive_capture(
        capture,
        Duration::from_millis(10),
        net::capture::Limits::default(),
        CaptureBudget {
            max_frames: 1,
            max_bytes: 2,
        },
        |_, _| {
            emitted = true;
            Ok(())
        },
    )
    .unwrap_err();

    assert!(!emitted);
    assert_eq!(error.exit_code, 6);
    assert_eq!(error.classification.code, "policy.byte_limit");
    assert_eq!(error.sequence, Some(0));
}

#[test]
fn pcapng_exchange_evidence_preserves_multiple_link_types() {
    let raw = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![0x45, 0, 0, 0]).unwrap();
    let ethernet = Frame::new(
        SystemTime::UNIX_EPOCH + Duration::from_nanos(1),
        LinkType::ETHERNET,
        vec![0; 14],
    )
    .unwrap();
    let bytes = encode_capture_file(
        output::contract::Format::Pcapng,
        [raw.clone(), ethernet.clone()],
    )
    .unwrap();
    let mut reader = Reader::new(std::io::Cursor::new(bytes)).unwrap();
    let decoded_raw = reader.next_frame().unwrap().unwrap();
    let decoded_ethernet = reader.next_frame().unwrap().unwrap();

    assert_eq!(decoded_raw.link_type, raw.link_type);
    assert_eq!(decoded_raw.bytes(), raw.bytes());
    assert_eq!(decoded_raw.interface, Some(0));
    assert_eq!(decoded_ethernet.link_type, ethernet.link_type);
    assert_eq!(decoded_ethernet.bytes(), ethernet.bytes());
    assert_eq!(decoded_ethernet.interface, Some(1));
    assert!(reader.next_frame().unwrap().is_none());

    let error = encode_capture_file(output::contract::Format::Pcap, [raw, ethernet]).unwrap_err();
    assert_eq!(error.exit_code, 5);
    assert!(error.message.contains("link type"));
}

#[test]
fn send_capture_evidence_uses_the_transmission_boundary_link_type() {
    assert_eq!(
        send_capture_link_type(net::link::Mode::Layer2, LinkType::ETHERNET).unwrap(),
        LinkType::ETHERNET
    );
    assert_eq!(
        send_capture_link_type(net::link::Mode::Layer3, LinkType::ETHERNET).unwrap(),
        LinkType::RAW
    );
    assert_eq!(
        send_capture_link_type(net::link::Mode::Layer3, LinkType(147)).unwrap(),
        LinkType::RAW
    );
    assert!(send_capture_link_type(net::link::Mode::Auto, LinkType::ETHERNET).is_err());
}

#[test]
fn replay_pcapng_evidence_preserves_source_timestamp_metadata() {
    let timestamp = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_millis(500))
        .unwrap();
    let mut frame = Frame::new(timestamp, LinkType::RAW, vec![0x60; 40]).unwrap();
    frame.interface = Some(7);
    let evidence = workflow::replay::FrameEvidence {
        source_sequence: 0,
        source_interface_id: Some(7),
        capture_interface: capture::Interface {
            link_type: LinkType::RAW,
            snap_len: 128,
            timestamp_resolution: capture::TimestampResolution::Binary(10),
            timestamp_offset: -1,
        },
        interface: net::interface::Id {
            name: "test0".to_owned(),
            index: 1,
        },
        link_mode: net::link::Mode::Layer3,
        scheduled_delay: Duration::ZERO,
        bytes_sent: 40,
        frame: frame.clone(),
    };
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    let mut interfaces = Vec::new();
    write_replay_capture_evidence(&mut writer, Format::PcapNg, &mut interfaces, evidence).unwrap();

    let mut reader = Reader::new(std::io::Cursor::new(writer.into_inner())).unwrap();
    let decoded = reader.next_frame().unwrap().unwrap();
    frame.interface = Some(0);
    assert_eq!(decoded, frame);
    assert_eq!(
        reader.interfaces()[0],
        capture::Interface {
            link_type: LinkType::RAW,
            snap_len: 128,
            timestamp_resolution: capture::TimestampResolution::Binary(10),
            timestamp_offset: -1,
        }
    );
}
