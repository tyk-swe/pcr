// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;

use packetcraftr_capture::Frame;
use packetcraftr_client::{
    Stats as ClientStats,
    exchange::{Response as ExchangeResponse, Result as ExchangeResult},
};
use packetcraftr_core::error::Classified;
use packetcraftr_net::{
    interface::{Flags as InterfaceFlags, Id as InterfaceId, Info as InterfaceInfo},
    link::Capability as LinkCapability,
};
use packetcraftr_packet::{
    Packet, build::BuiltPacket, decode::DecodedPacket, layout::PacketLayout,
};
use packetcraftr_workflow::{
    Stats as WorkflowStats,
    dns::{
        Outcome as DomainDnsOutcome, QueryType as DnsQueryType, Record as DnsRecord,
        RecordValue as DnsRecordValue, Result as DnsResult,
        ValidatedResponse as ValidatedDnsResponse,
    },
    scan::{
        Classification as DomainScanClassification, Endpoint as ScanEndpointResult,
        ProbeEvidence as ScanProbeEvidence, ProbeStatus as DomainScanProbeStatus,
        Result as ScanResult, Transport as ScanTransport,
    },
    traceroute::{
        Completion as TracerouteCompletion, Hop as TracerouteHopResult,
        ProbeEvidence as TracerouteProbeEvidence, ProbeStatus as TracerouteProbeStatus,
        ResponseKind as TracerouteResponseKind, Result as TracerouteResult,
        Strategy as TracerouteStrategy,
    },
};

use super::contract::{
    CONTRACTS as COMMAND_OUTPUT_CONTRACTS, Command as CommandName, Format as OutputFormat,
};
use super::dns::{
    AttemptStatus as DnsAttemptStatus, RecordData as DnsRecordData, Result as DnsCommandResult,
};
use super::envelope::{Aggregate as AggregateOutput, Stream as StreamRecord};
use super::exchange::Result as ExchangeCommandResult;
use super::frame::{Captured as FrameOutput, Timestamp as OutputTimestamp};
use super::fuzz::Outcome as FuzzCaseOutcome;
use super::interfaces::Result as InterfacesCommandResult;
use super::read::Result as ReadFrameCommandResult;
use super::routes::Result as RoutesCommandResult;
use super::scan::{Classification as ScanClassification, Result as ScanCommandResult};
use super::traceroute::{Completion as TraceCompletionReason, Result as TracerouteCommandResult};

const EXPECTED_BUILD_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Hex,
    OutputFormat::Raw,
];
const EXPECTED_AGGREGATE_FORMATS: &[OutputFormat] = &[OutputFormat::Text, OutputFormat::Json];
const EXPECTED_SEND_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Hex,
    OutputFormat::Raw,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const EXPECTED_EXCHANGE_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Ndjson,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const EXPECTED_CAPTURE_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Ndjson,
    OutputFormat::Hex,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const EXPECTED_REPLAY_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Ndjson,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const EXPECTED_TOOL_FORMATS: &[OutputFormat] =
    &[OutputFormat::Text, OutputFormat::Json, OutputFormat::Ndjson];
const EXPECTED_FOLLOW_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Ndjson,
    OutputFormat::Hex,
    OutputFormat::Raw,
];

fn expected_formats(command: CommandName) -> &'static [OutputFormat] {
    match command {
        CommandName::Build | CommandName::Dissect => EXPECTED_BUILD_FORMATS,
        CommandName::Protocols
        | CommandName::Plan
        | CommandName::Interfaces
        | CommandName::Routes
        | CommandName::Stats => EXPECTED_AGGREGATE_FORMATS,
        CommandName::Send => EXPECTED_SEND_FORMATS,
        CommandName::Exchange => EXPECTED_EXCHANGE_FORMATS,
        CommandName::Capture | CommandName::Read => EXPECTED_CAPTURE_FORMATS,
        CommandName::Replay => EXPECTED_REPLAY_FORMATS,
        CommandName::Follow => EXPECTED_FOLLOW_FORMATS,
        CommandName::Scan
        | CommandName::Traceroute
        | CommandName::Dns
        | CommandName::Fuzz
        | CommandName::Expert => EXPECTED_TOOL_FORMATS,
    }
}

#[test]
fn command_name_vocabulary_has_unique_variants_and_serialized_names() {
    let mut variants = HashSet::new();
    let mut serialized_names = HashSet::new();

    for command in CommandName::ALL {
        assert!(
            variants.insert(*command),
            "duplicate command variant: {command}"
        );
        assert!(
            serialized_names.insert(command.as_str()),
            "duplicate serialized command name: {command}"
        );
        assert_eq!(
            serde_json::to_value(command).unwrap().as_str(),
            Some(command.as_str()),
            "serialized spelling drifted for {command}"
        );
    }
}

#[test]
fn command_output_contracts_cover_vocabulary_once_in_canonical_order() {
    assert_eq!(COMMAND_OUTPUT_CONTRACTS.len(), CommandName::ALL.len());

    let mut contract_commands = HashSet::new();
    let mut serialized_contract_names = HashSet::new();
    for (command, contract) in CommandName::ALL.iter().zip(COMMAND_OUTPUT_CONTRACTS.iter()) {
        assert_eq!(contract.command, *command, "command contract order drifted");
    }

    for command in CommandName::ALL {
        let matches = COMMAND_OUTPUT_CONTRACTS
            .iter()
            .filter(|contract| contract.command == *command)
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one output contract for {command}"
        );
    }

    for contract in COMMAND_OUTPUT_CONTRACTS {
        assert!(
            CommandName::ALL.contains(&contract.command),
            "output contract has command outside the authoritative vocabulary: {}",
            contract.command
        );
        assert!(
            contract_commands.insert(contract.command),
            "duplicate output contract for {}",
            contract.command
        );
        assert!(
            serialized_contract_names.insert(contract.command.as_str()),
            "duplicate serialized output contract name: {}",
            contract.command
        );
    }
}

#[test]
fn command_output_contracts_have_exact_supported_formats() {
    const ALL_FORMATS: &[OutputFormat] = &[
        OutputFormat::Text,
        OutputFormat::Json,
        OutputFormat::Ndjson,
        OutputFormat::Hex,
        OutputFormat::Raw,
        OutputFormat::Pcap,
        OutputFormat::Pcapng,
    ];

    for contract in COMMAND_OUTPUT_CONTRACTS {
        assert_eq!(
            contract.formats,
            expected_formats(contract.command),
            "supported format set drifted for {}",
            contract.command
        );
        assert!(!contract.formats.is_empty());
        for (index, format) in contract.formats.iter().enumerate() {
            assert!(!contract.formats[..index].contains(format));
        }
        for format in ALL_FORMATS {
            assert_eq!(
                contract.command.require_format(*format).is_ok(),
                contract.formats.contains(format),
                "{} / {}",
                contract.command,
                format
            );
        }
    }
}

#[test]
fn interface_output_has_stable_interface_and_address_ordering() {
    let interface = |index, name: &str, addresses: &[(&str, u8)]| InterfaceInfo {
        id: InterfaceId {
            name: name.to_owned(),
            index,
        },
        description: None,
        mac_address: None,
        addresses: addresses
            .iter()
            .map(
                |(address, prefix_length)| packetcraftr_net::interface::Address {
                    address: address.parse().unwrap(),
                    prefix_length: *prefix_length,
                },
            )
            .collect(),
        flags: InterfaceFlags::default(),
        mtu: None,
        capability: LinkCapability::Layer3,
        link_type: packetcraftr_capture::LinkType::RAW,
    };
    let result = InterfacesCommandResult::new(vec![
        interface(7, "zeta", &[("2001:db8::1", 64), ("10.0.0.2", 24)]),
        interface(2, "beta", &[]),
        interface(2, "alpha", &[]),
    ]);

    assert_eq!(
        result
            .interfaces
            .iter()
            .map(|interface| (interface.index, interface.name.as_str()))
            .collect::<Vec<_>>(),
        [(2, "alpha"), (2, "beta"), (7, "zeta")]
    );
    assert_eq!(
        result.interfaces[2].addresses,
        ["10.0.0.2/24", "2001:db8::1/64"]
    );
}

#[test]
fn workflow_enums_convert_to_output_owned_v1_spellings() {
    assert_eq!(
        serde_json::to_value(ScanClassification::from(
            packetcraftr_workflow::scan::Classification::Filtered,
        ))
        .unwrap(),
        "filtered"
    );
    assert_eq!(
        serde_json::to_value(TraceCompletionReason::from(
            packetcraftr_workflow::traceroute::Completion::MaximumHops,
        ))
        .unwrap(),
        "maximum_hops"
    );
    assert_eq!(
        serde_json::to_value(DnsAttemptStatus::from(
            packetcraftr_workflow::dns::AttemptStatus::DecodeFailure,
        ))
        .unwrap(),
        "decode_failure"
    );
    assert_eq!(
        serde_json::to_value(FuzzCaseOutcome::from(
            packetcraftr_workflow::fuzz::CaseOutcome::Rejected,
        ))
        .unwrap(),
        "rejected"
    );
}

#[test]
fn aggregate_and_stream_envelopes_freeze_mode_and_sequence() {
    let aggregate = AggregateOutput::success(
        CommandName::Routes,
        RoutesCommandResult { routes: Vec::new() },
        Vec::new(),
    );
    let value = serde_json::to_value(aggregate).unwrap();
    assert_eq!(value["mode"], "aggregate");
    assert!(value.get("sequence").is_none());

    let stream = StreamRecord::success(
        CommandName::Read,
        7,
        ReadFrameCommandResult {
            frame: FrameOutput::try_from_frame(
                Frame::new(UNIX_EPOCH, packetcraftr_capture::LinkType::RAW, vec![0_u8]).unwrap(),
            )
            .unwrap(),
            decoded: None,
        },
        Vec::new(),
    );
    let value = serde_json::to_value(stream).unwrap();
    assert_eq!(value["mode"], "stream");
    assert_eq!(value["sequence"], 7);
}

#[test]
fn dns_output_preserves_exact_txt_bytes_and_json_escapes_controls() {
    let exact = Bytes::from_static(b"remote\x1b[31m");
    let result = DnsResult {
        server: "10.0.0.53".to_owned(),
        server_port: 53,
        resolved_addresses: vec!["10.0.0.53".parse().unwrap()],
        query_name: "txt.example.".to_owned(),
        query_type: DnsQueryType::Txt,
        transaction_id: 7,
        outcome: DomainDnsOutcome::Response,
        response: Some(ValidatedDnsResponse {
            transaction_id: 7,
            response_code: 0,
            edns: None,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authenticated_data: false,
            checking_disabled: false,
            answers: vec![DnsRecord {
                owner: packetcraftr_workflow::dns::Name::from_labels([
                    Bytes::from_static(b"txt"),
                    Bytes::from_static(b"example"),
                ])
                .unwrap(),
                class: 1,
                ttl: 60,
                value: DnsRecordValue::Txt(vec![exact]),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
            rejected_records: Vec::new(),
            rejected_record_count: 0,
        }),
        attempts: Vec::new(),
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats: WorkflowStats::default(),
    };
    let (output, _, _) = DnsCommandResult::try_from_dns(result).unwrap();
    assert_eq!(output.transport, "udp");
    let DnsRecordData::Txt {
        strings,
        strings_hex,
    } = &output.answers[0].data
    else {
        panic!("expected TXT output");
    };
    assert_eq!(strings_hex, &["72656d6f74651b5b33316d"]);
    assert_eq!(strings[0].as_bytes(), b"remote\x1b[31m");
    let json = serde_json::to_string(&output).unwrap();
    assert!(!json.contains('\x1b'));
    assert!(json.contains("\\u001b"));
}

#[test]
fn pre_epoch_timestamps_use_canonical_signed_unix_parts() {
    let timestamp = UNIX_EPOCH
        .checked_sub(Duration::new(2, 250_000_000))
        .unwrap();
    assert_eq!(
        OutputTimestamp::try_from(timestamp).unwrap(),
        OutputTimestamp {
            unix_seconds: -3,
            nanoseconds: 750_000_000,
        }
    );
}

#[test]
fn fractional_pre_epoch_timestamp_accepts_the_signed_seconds_minimum() {
    assert_eq!(
        OutputTimestamp::from_pre_epoch_duration(Duration::new(i64::MAX as u64, 250_000_000,))
            .unwrap(),
        OutputTimestamp {
            unix_seconds: i64::MIN,
            nanoseconds: 750_000_000,
        }
    );
}

#[test]
fn frame_results_preserve_capture_fields() {
    let frame = Frame::new(UNIX_EPOCH, packetcraftr_capture::LinkType::RAW, vec![0_u8]).unwrap();
    let output = FrameOutput::try_from_frame(frame).unwrap();
    assert_eq!(output.captured_length, 1);
    assert_eq!(output.original_length, 1);
    assert_eq!(output.bytes(), &[0]);
}

#[test]
fn exchange_output_preserves_every_evidence_family_and_operation_stats() {
    let captured = |bytes: &'static [u8]| {
        Frame::new(
            UNIX_EPOCH + Duration::from_secs(7),
            packetcraftr_capture::LinkType::RAW,
            bytes.to_vec(),
        )
        .unwrap()
    };
    let decoded = |bytes: &'static [u8]| DecodedPacket {
        packet: Packet::new(),
        original: Bytes::from_static(bytes),
        frame: captured(bytes),
        layout: PacketLayout::default(),
        diagnostics: Vec::new(),
    };
    let result = ExchangeResult {
        sent: vec![BuiltPacket {
            bytes: Bytes::from_static(b"request"),
            packet: Packet::new(),
            layout: PacketLayout::default(),
            diagnostics: Vec::new(),
            requires_live_opt_in: false,
        }],
        sent_evidence: vec![captured(b"request")],
        responses: vec![ExchangeResponse {
            request_index: 0,
            response: decoded(b"response"),
            latency: Duration::from_millis(4),
        }],
        unanswered: vec![2],
        unsolicited: vec![decoded(b"unsolicited")],
        undecoded: vec![captured(b"undecoded")],
        diagnostics: Vec::new(),
        stats: ClientStats {
            packets_attempted: 2,
            packets_completed: 1,
            bytes: 23,
            elapsed: Duration::from_millis(9),
            capture: packetcraftr_net::capture::Statistics::default(),
        },
    };

    let (output, diagnostics, stats) = ExchangeCommandResult::try_from_exchange(result).unwrap();

    assert!(diagnostics.is_empty());
    assert_eq!(output.sent[0].bytes(), b"request");
    assert_eq!(output.responses[0].request_index, 0);
    assert_eq!(output.responses[0].response.frame.bytes(), b"response");
    assert_eq!(output.responses[0].latency, Duration::from_millis(4));
    assert_eq!(output.unanswered, [2]);
    assert_eq!(output.unsolicited[0].frame.bytes(), b"unsolicited");
    assert_eq!(output.undecoded[0].bytes(), b"undecoded");
    assert_eq!(stats.packets_attempted, 2);
    assert_eq!(stats.packets_completed, 1);
    assert_eq!(stats.bytes, 23);
    assert_eq!(stats.elapsed, Duration::from_millis(9));
}

#[test]
fn unsupported_format_errors_name_all_supported_choices() {
    let error = CommandName::Read
        .require_format(OutputFormat::Json)
        .unwrap_err();
    assert_eq!(error.classification().code, "cli.output_format");
    assert_eq!(
        error.to_string(),
        "read does not support json output; choose text, ndjson, hex, pcap, pcapng"
    );
}

#[test]
fn capture_and_replay_formats_are_stable() {
    assert_eq!(
        CommandName::Protocols.formats(),
        &[OutputFormat::Text, OutputFormat::Json]
    );
    assert_eq!(
        CommandName::Read.formats(),
        &[
            OutputFormat::Text,
            OutputFormat::Ndjson,
            OutputFormat::Hex,
            OutputFormat::Pcap,
            OutputFormat::Pcapng,
        ]
    );
    assert_eq!(
        CommandName::Replay.formats(),
        &[
            OutputFormat::Text,
            OutputFormat::Json,
            OutputFormat::Ndjson,
            OutputFormat::Pcap,
            OutputFormat::Pcapng,
        ]
    );
}

#[test]
fn scan_output_preserves_per_attempt_facts_and_timeout_classification() {
    let address: IpAddr = "192.168.56.10".parse().unwrap();
    let result = ScanResult {
        target: address.to_string(),
        resolved_addresses: vec![address],
        endpoints: vec![ScanEndpointResult {
            address,
            transport: ScanTransport::Tcp,
            port: Some(443),
            classification: DomainScanClassification::Timeout,
            evidence: vec![ScanProbeEvidence {
                attempt: 1,
                status: DomainScanProbeStatus::Timeout,
                classification: DomainScanClassification::Timeout,
                responder: None,
                sent_at: UNIX_EPOCH + Duration::from_secs(7),
                received_at: None,
                latency: None,
                response: None,
                reason: "bounded timeout".to_owned(),
            }],
        }],
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats: WorkflowStats {
            packets_attempted: 1,
            packets_completed: 1,
            bytes: 40,
            elapsed: Duration::from_secs(1),
            capture: packetcraftr_net::capture::Statistics::default(),
        },
    };

    let (result, diagnostics, stats) = ScanCommandResult::try_from_scan(result).unwrap();
    let value = serde_json::to_value(
        AggregateOutput::success(CommandName::Scan, result, diagnostics).with_stats(stats),
    )
    .unwrap();
    assert_eq!(value["result"]["ports"][0]["classification"], "timeout");
    assert_eq!(value["result"]["ports"][0]["evidence"][0]["attempt"], 1);
    assert_eq!(
        value["result"]["ports"][0]["evidence"][0]["status"],
        "timeout"
    );
    assert!(
        value["result"]["ports"][0]["evidence"][0]
            .get("received_at")
            .is_none()
    );
    assert_eq!(value["stats"]["packets_completed"], 1);
}

#[test]
fn traceroute_output_preserves_typed_per_attempt_timing_and_terminal_evidence() {
    let destination: IpAddr = "192.168.56.10".parse().unwrap();
    let responder: IpAddr = "192.168.56.1".parse().unwrap();
    let result = TracerouteResult {
        target: "router.lab".to_owned(),
        resolved_addresses: vec![destination],
        destination,
        strategy: TracerouteStrategy::Udp,
        destination_port: Some(33_434),
        hops: vec![TracerouteHopResult {
            hop_limit: 1,
            probes: vec![TracerouteProbeEvidence {
                sequence: 0,
                hop_limit: 1,
                attempt: 1,
                destination,
                strategy: TracerouteStrategy::Udp,
                destination_port: Some(33_434),
                status: TracerouteProbeStatus::Response,
                response_kind: Some(TracerouteResponseKind::Intermediate),
                responder: Some(responder),
                sent_at: UNIX_EPOCH + Duration::from_secs(7),
                received_at: Some(UNIX_EPOCH + Duration::from_secs(7) + Duration::from_millis(4)),
                latency: Some(Duration::from_millis(4)),
                response: None,
                reason: "correlated time exceeded".to_owned(),
            }],
        }],
        undecoded: Vec::new(),
        completion: TracerouteCompletion::MaximumHops,
        diagnostics: Vec::new(),
        stats: WorkflowStats {
            packets_attempted: 1,
            packets_completed: 1,
            bytes: 60,
            elapsed: Duration::from_millis(10),
            capture: packetcraftr_net::capture::Statistics::default(),
        },
    };

    let (result, diagnostics, stats) =
        TracerouteCommandResult::try_from_traceroute(result).unwrap();
    let value = serde_json::to_value(
        AggregateOutput::success(CommandName::Traceroute, result, diagnostics).with_stats(stats),
    )
    .unwrap();
    assert_eq!(value["result"]["destination"], "192.168.56.10");
    assert_eq!(value["result"]["hops"][0]["probes"][0]["sequence"], 0);
    assert_eq!(
        value["result"]["hops"][0]["probes"][0]["response_kind"],
        "intermediate"
    );
    assert_eq!(
        value["result"]["hops"][0]["probes"][0]["latency"]["nanos"],
        4_000_000
    );
    assert_eq!(value["result"]["completion"], "maximum_hops");
    assert_eq!(value["stats"]["packets_completed"], 1);
}
