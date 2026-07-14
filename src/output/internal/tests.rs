use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;

use crate::capture::Frame;
use crate::error::Classified;
use crate::net::{
    interface::{Flags as InterfaceFlags, Id as InterfaceId, Info as InterfaceInfo},
    link::Capability as LinkCapability,
};
use crate::workflow::{
    Stats as WorkflowStats,
    dns::{
        Outcome as DomainDnsOutcome, QueryType as DnsQueryType, Record as DnsRecord,
        RecordValue as DnsRecordValue, Result as DnsResult, Transport as DnsTransport,
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

use super::capture::ReadFrameCommandResult;
use super::contract::{
    COMMAND_OUTPUT_CONTRACTS, CommandName, OutputFormat, READ_FORMATS, REPLAY_FORMATS,
};
use super::dns::{DnsAttemptStatus, DnsCommandResult, DnsRecordData};
use super::envelope::{AggregateOutput, StreamRecord};
use super::frame::{FrameOutput, OutputTimestamp};
use super::fuzz::FuzzCaseOutcome;
use super::network::{InterfacesCommandResult, RoutesCommandResult};
use super::scan::{ScanClassification, ScanCommandResult};
use super::traceroute::{TraceCompletionReason, TracerouteCommandResult};

#[test]
fn command_matrix_is_complete_and_has_no_duplicate_formats() {
    const ALL_FORMATS: &[OutputFormat] = &[
        OutputFormat::Text,
        OutputFormat::Json,
        OutputFormat::Ndjson,
        OutputFormat::Hex,
        OutputFormat::Raw,
        OutputFormat::Pcap,
        OutputFormat::Pcapng,
    ];
    assert_eq!(COMMAND_OUTPUT_CONTRACTS.len(), 14);
    for (contract_index, contract) in COMMAND_OUTPUT_CONTRACTS.iter().enumerate() {
        assert!(!contract.formats.is_empty());
        assert_eq!(contract.formats, contract.command.formats());
        assert!(
            !COMMAND_OUTPUT_CONTRACTS[..contract_index]
                .iter()
                .any(|prior| prior.command == contract.command)
        );
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
            .map(|(address, prefix_length)| crate::net::interface::Address {
                address: address.parse().unwrap(),
                prefix_length: *prefix_length,
            })
            .collect(),
        flags: InterfaceFlags::default(),
        mtu: None,
        capability: LinkCapability::Layer3,
        link_type: crate::capture::LinkType::RAW,
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
            crate::workflow::scan::Classification::Filtered,
        ))
        .unwrap(),
        "filtered"
    );
    assert_eq!(
        serde_json::to_value(TraceCompletionReason::from(
            crate::workflow::traceroute::Completion::MaximumHops,
        ))
        .unwrap(),
        "maximum_hops"
    );
    assert_eq!(
        serde_json::to_value(DnsAttemptStatus::from(
            crate::workflow::dns::AttemptStatus::DecodeFailure,
        ))
        .unwrap(),
        "decode_failure"
    );
    assert_eq!(
        serde_json::to_value(FuzzCaseOutcome::from(
            crate::workflow::fuzz::CaseOutcome::Rejected,
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
                Frame::new(UNIX_EPOCH, crate::capture::LinkType::RAW, vec![0_u8]).unwrap(),
            )
            .unwrap(),
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
        transport: DnsTransport::Udp,
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
                owner: crate::workflow::dns::Name::from_labels([
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
    let frame = Frame::new(UNIX_EPOCH, crate::capture::LinkType::RAW, vec![0_u8]).unwrap();
    let output = FrameOutput::try_from_frame(frame).unwrap();
    assert_eq!(output.captured_length, 1);
    assert_eq!(output.original_length, 1);
    assert_eq!(output.bytes(), &[0]);
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
    assert_eq!(CommandName::Read.formats(), READ_FORMATS);
    assert_eq!(CommandName::Replay.formats(), REPLAY_FORMATS);
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
            capture: crate::net::capture::Statistics::default(),
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
            capture: crate::net::capture::Statistics::default(),
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
