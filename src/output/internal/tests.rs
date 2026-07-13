#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{
        dns::{
            AttemptEvidence as DnsAttemptEvidence, AttemptStatus as DomainDnsAttemptStatus,
            Edns as DomainDnsEdns, EdnsOption as DomainDnsEdnsOption,
            Name as DomainDnsName, Outcome as DomainDnsOutcome, QueryType as DnsQueryType,
            Record as DnsRecord, RecordValue as DnsRecordValue,
            RejectedRecord as DomainDnsRejectedRecord, Section as DomainDnsSection,
            Transport as DnsTransport, UndecodedEvidence as DnsUndecodedEvidence,
            ValidatedResponse as ValidatedDnsResponse,
        },
        scan::{
            Classification as DomainScanClassification, Endpoint as ScanEndpointResult,
            ProbeEvidence as ScanProbeEvidence, ProbeStatus as DomainScanProbeStatus,
            Transport as ScanTransport,
        },
        traceroute::{
            Completion as TracerouteCompletion, Hop as TracerouteHopResult,
            ProbeEvidence as TracerouteProbeEvidence, ProbeStatus as TracerouteProbeStatus,
            ResponseKind as TracerouteResponseKind, Strategy as TracerouteStrategy,
        },
        Stats as WorkflowStats,
    };

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
        assert_eq!(COMMAND_OUTPUT_CONTRACTS.len(), 15);
        for (contract_index, contract) in COMMAND_OUTPUT_CONTRACTS.iter().enumerate() {
            assert!(!contract.formats.is_empty());
            assert_eq!(contract.formats, contract.command.formats());
            assert!(!COMMAND_OUTPUT_CONTRACTS[..contract_index]
                .iter()
                .any(|prior| prior.command == contract.command));
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
    fn workflow_enums_convert_to_output_owned_v2_spellings() {
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
    fn decoded_exchange_layout_offsets_use_output_v2_decimal_strings() {
        let frame = Frame::new(
            UNIX_EPOCH,
            crate::capture::LinkType::RAW,
            Bytes::from_static(&[0]),
        )
        .unwrap();
        let decoded = DecodedPacket {
            packet: crate::packet::Packet::default(),
            original: frame.bytes.clone(),
            frame,
            layout: PacketLayout {
                layers: vec![crate::packet::layout::Layer {
                    index: 7,
                    protocol: crate::packet::layer::Id::new("raw"),
                    range: crate::packet::layout::Range::new(11, 13),
                    fields: vec![crate::packet::layout::Field {
                        name: "bytes".to_owned(),
                        range: crate::packet::layout::Range::new(11, 12),
                    }],
                }],
            },
            diagnostics: Vec::new(),
        };

        let value = serde_json::to_value(DecodedFrameOutput::try_from_decoded(decoded).unwrap())
            .unwrap();
        assert_eq!(value["layout"]["layers"][0]["index"], "7");
        assert_eq!(value["layout"]["layers"][0]["range"]["start"], "11");
        assert_eq!(value["layout"]["layers"][0]["range"]["end"], "13");
        assert_eq!(
            value["layout"]["layers"][0]["fields"][0]["range"]["start"],
            "11"
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
        assert_eq!(value["sequence"], "7");
    }

    #[test]
    fn envelope_error_categories_and_complete_lifecycle_records_are_explicit() {
        let kinds = [
            Kind::Cli,
            Kind::Packet,
            Kind::Capability,
            Kind::Io,
            Kind::Policy,
            Kind::Internal,
        ];
        assert_eq!(
            kinds
                .into_iter()
                .map(|kind| OutputErrorKind::from(kind).as_str())
                .collect::<Vec<_>>(),
            ["cli", "packet", "capability", "io", "policy", "internal"]
        );
        let categories = [
            Category::Validation,
            Category::Capability,
            Category::Policy,
            Category::Timeout,
            Category::Io,
            Category::Cleanup,
            Category::Invariant,
        ];
        assert_eq!(
            categories
                .into_iter()
                .map(|category| serde_json::to_value(OutputErrorCategory::from(category)).unwrap())
                .collect::<Vec<_>>(),
            [
                serde_json::json!("validation"),
                serde_json::json!("capability"),
                serde_json::json!("policy"),
                serde_json::json!("timeout"),
                serde_json::json!("io"),
                serde_json::json!("cleanup"),
                serde_json::json!("invariant"),
            ]
        );

        let context = EnvelopeContext::new(
            OperationId::from_bytes([9; 16]),
            serde_json::json!({"normalized": true}),
        )
        .with_diagnostics(vec![Diagnostic::warning("test.context", "context warning")]);
        let classified = crate::net::LiveIoError::DeadlineExceeded {
            operation: "test output",
        };
        let error = OutputError::classified(&classified);
        assert_eq!(error.category, OutputErrorCategory::Timeout);

        let aggregate = AggregateErrorOutput::error(Some(CommandName::Capture), error.clone())
            .with_context(&context)
            .with_completion_reason(CompletionReason::Timeout)
            .with_stats(OperationStats::default())
            .with_diagnostics(vec![Diagnostic::warning(
                "test.aggregate",
                "aggregate warning",
            )]);
        let aggregate = serde_json::to_value(aggregate).unwrap();
        assert_eq!(aggregate["operation_id"], OperationId::from_bytes([9; 16]).to_string());
        assert_eq!(aggregate["completion_reason"], "timeout");
        assert_eq!(aggregate["error"]["category"], "timeout");
        assert_eq!(aggregate["stats"]["packets_attempted"], "0");

        let cancelled = serde_json::to_value(
            AggregateErrorOutput::cancelled(Some(CommandName::Capture), error.clone())
                .with_context(&context),
        )
        .unwrap();
        assert_eq!(cancelled["status"], "cancelled");
        assert_eq!(cancelled["completion_reason"], "cancelled");

        let start = serde_json::to_value(StreamRecord::<()>::start(
            Some(CommandName::Capture),
            &context,
        ))
        .unwrap();
        assert_eq!(start["record"], "start");
        assert_eq!(start["effective_request"]["normalized"], true);

        let complete = serde_json::to_value(
            StreamRecord::success(
                CommandName::Capture,
                1,
                serde_json::json!({"frames": "0"}),
                Vec::new(),
            )
            .complete(CompletionReason::EndOfInput)
            .with_context(&context)
            .with_stats(OperationStats::default())
            .with_diagnostics(vec![Diagnostic::warning(
                "test.complete",
                "complete warning",
            )]),
        )
        .unwrap();
        assert_eq!(complete["record"], "complete");
        assert_eq!(complete["completion_reason"], "end_of_input");

        let terminal_error = serde_json::to_value(StreamErrorRecord::error(
            Some(CommandName::Capture),
            2,
            error.clone(),
        ))
        .unwrap();
        assert_eq!(terminal_error["record"], "error");
        let terminal_cancelled = serde_json::to_value(StreamErrorRecord::cancelled(
            Some(CommandName::Capture),
            3,
            error,
        ))
        .unwrap();
        assert_eq!(terminal_cancelled["record"], "cancelled");
    }

    #[test]
    fn command_and_format_spellings_cover_the_frozen_contract() {
        assert_eq!(
            COMMAND_OUTPUT_CONTRACTS
                .iter()
                .map(|contract| contract.command.as_str())
                .collect::<Vec<_>>(),
            [
                "build",
                "dissect",
                "plan",
                "send",
                "exchange",
                "capture",
                "read",
                "replay",
                "scan",
                "traceroute",
                "dns",
                "fuzz",
                "interfaces",
                "routes",
                "doctor",
            ]
        );
        let formats = [
            OutputFormat::Text,
            OutputFormat::Json,
            OutputFormat::Ndjson,
            OutputFormat::Hex,
            OutputFormat::Raw,
            OutputFormat::Pcap,
            OutputFormat::Pcapng,
        ];
        assert_eq!(
            formats
                .into_iter()
                .map(|format| (format.as_str(), format.mode()))
                .collect::<Vec<_>>(),
            [
                ("text", None),
                ("json", Some(OutputMode::Aggregate)),
                ("ndjson", Some(OutputMode::Stream)),
                ("hex", None),
                ("raw", None),
                ("pcap", None),
                ("pcapng", None),
            ]
        );
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
    fn dns_output_preserves_every_typed_record_and_evidence_shape() {
        let name = |label: &'static [u8]| {
            DomainDnsName::from_labels([Bytes::from_static(label)]).unwrap()
        };
        let owner = name(b"example");
        let edns = DomainDnsEdns {
            udp_payload_size: 1232,
            extended_response_code: 1,
            version: 0,
            dnssec_ok: true,
            flags: 0x8000,
            options: vec![DomainDnsEdnsOption {
                code: 15,
                data: Bytes::from_static(&[0xde, 0xad]),
            }],
        };
        let values = vec![
            DnsRecordValue::A("192.0.2.1".parse().unwrap()),
            DnsRecordValue::Aaaa("2001:db8::1".parse().unwrap()),
            DnsRecordValue::Cname(name(b"canonical")),
            DnsRecordValue::Mx {
                preference: 10,
                exchange: name(b"mail"),
            },
            DnsRecordValue::Ns(name(b"nameserver")),
            DnsRecordValue::Ptr(name(b"pointer")),
            DnsRecordValue::Soa {
                primary_name_server: name(b"primary"),
                responsible_mailbox: name(b"mailbox"),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 5,
            },
            DnsRecordValue::Srv {
                priority: 1,
                weight: 2,
                port: 443,
                target: name(b"service"),
            },
            DnsRecordValue::Txt(vec![Bytes::from_static(b"text")]),
            DnsRecordValue::Opt(edns.clone()),
            DnsRecordValue::Unknown {
                type_code: 65_000,
                rdata: Bytes::from_static(&[0xca, 0xfe]),
            },
        ];
        let records = values
            .into_iter()
            .map(|value| DnsRecord {
                owner: owner.clone(),
                class: 1,
                ttl: 60,
                value,
            })
            .collect::<Vec<_>>();
        let response_frame = Frame::new(
            UNIX_EPOCH + Duration::from_secs(2),
            crate::capture::LinkType::RAW,
            vec![0x45],
        )
        .unwrap();
        let result = DnsResult {
            server: "192.0.2.53".to_owned(),
            server_port: 53,
            resolved_addresses: vec!["192.0.2.53".parse().unwrap()],
            query_name: "example.".to_owned(),
            query_type: DnsQueryType::A,
            transaction_id: 9,
            transport: DnsTransport::Udp,
            outcome: DomainDnsOutcome::Truncated,
            response: Some(ValidatedDnsResponse {
                transaction_id: 9,
                response_code: 0,
                edns: Some(edns),
                authoritative: true,
                truncated: true,
                recursion_desired: true,
                recursion_available: false,
                authenticated_data: true,
                checking_disabled: false,
                answers: records,
                authorities: Vec::new(),
                additionals: Vec::new(),
                rejected_records: vec![
                    DomainDnsRejectedRecord {
                        section: DomainDnsSection::Answer,
                        index: 0,
                        owner: "answer.example.".to_owned(),
                        type_code: 1,
                        reason: "answer rejected".to_owned(),
                    },
                    DomainDnsRejectedRecord {
                        section: DomainDnsSection::Authority,
                        index: 1,
                        owner: "authority.example.".to_owned(),
                        type_code: 2,
                        reason: "authority rejected".to_owned(),
                    },
                    DomainDnsRejectedRecord {
                        section: DomainDnsSection::Additional,
                        index: 2,
                        owner: "additional.example.".to_owned(),
                        type_code: 41,
                        reason: "additional rejected".to_owned(),
                    },
                ],
                rejected_record_count: 3,
            }),
            attempts: vec![DnsAttemptEvidence {
                attempt: 1,
                server_address: "192.0.2.53".parse().unwrap(),
                source_port: 50_000,
                status: DomainDnsAttemptStatus::Truncated,
                sent_at: UNIX_EPOCH + Duration::from_secs(1),
                received_at: Some(UNIX_EPOCH + Duration::from_secs(2)),
                latency: Some(Duration::from_secs(1)),
                response: Some(response_frame.clone()),
                response_code: Some(0),
                reason: "truncated response".to_owned(),
            }],
            undecoded: vec![DnsUndecodedEvidence {
                attempt: 1,
                frame: response_frame,
            }],
            diagnostics: Vec::new(),
            stats: WorkflowStats::default(),
        };

        let (output, _, _) = DnsCommandResult::try_from_dns(result).unwrap();
        let output = serde_json::to_value(output).unwrap();
        assert_eq!(
            output["answers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|record| record["type"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "a", "aaaa", "cname", "mx", "ns", "ptr", "soa", "srv", "txt", "opt",
                "unknown",
            ]
        );
        assert_eq!(output["answers"][9]["edns"]["options"][0]["data_hex"], "dead");
        assert_eq!(output["answers"][10]["rdata_hex"], "cafe");
        assert_eq!(output["attempts"][0]["status"], "truncated");
        assert_eq!(output["undecoded"][0]["attempt"], 1);
        assert_eq!(
            output["rejected_records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|record| record["section"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["answer", "authority", "additional"]
        );

        for section in [DnsSection::Answer, DnsSection::Authority, DnsSection::Additional] {
            assert_eq!(section.to_string(), serde_json::to_value(section).unwrap());
        }
        for status in [
            DomainDnsAttemptStatus::Response,
            DomainDnsAttemptStatus::Truncated,
            DomainDnsAttemptStatus::Timeout,
            DomainDnsAttemptStatus::Unrelated,
            DomainDnsAttemptStatus::DecodeFailure,
            DomainDnsAttemptStatus::NetworkFailure,
        ] {
            let _: DnsAttemptStatus = status.into();
        }
        for outcome in [
            DomainDnsOutcome::Response,
            DomainDnsOutcome::Truncated,
            DomainDnsOutcome::Timeout,
            DomainDnsOutcome::Unrelated,
            DomainDnsOutcome::DecodeFailure,
            DomainDnsOutcome::NetworkFailure,
        ] {
            let _: DnsOutcome = outcome.into();
        }
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
    fn frame_results_revalidate_public_capture_fields() {
        let mut frame = Frame::new(UNIX_EPOCH, crate::capture::LinkType::RAW, vec![0_u8]).unwrap();
        frame.captured_length = 2;
        let error = FrameOutput::try_from_frame(frame).unwrap_err();
        assert_eq!(error.classification().code, "packet.capture_record");
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
        assert!(value["result"]["ports"][0]["evidence"][0]
            .get("received_at")
            .is_none());
        assert_eq!(value["stats"]["packets_completed"], "1");
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
                    received_at: Some(
                        UNIX_EPOCH + Duration::from_secs(7) + Duration::from_millis(4),
                    ),
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
            AggregateOutput::success(CommandName::Traceroute, result, diagnostics)
                .with_stats(stats),
        )
        .unwrap();
        assert_eq!(value["result"]["destination"], "192.168.56.10");
        assert_eq!(value["result"]["hops"][0]["probes"][0]["sequence"], "0");
        assert_eq!(
            value["result"]["hops"][0]["probes"][0]["response_kind"],
            "intermediate"
        );
        assert_eq!(
            value["result"]["hops"][0]["probes"][0]["latency"]["nanoseconds"],
            4_000_000
        );
        assert_eq!(value["result"]["completion"], "maximum_hops");
        assert_eq!(value["stats"]["packets_completed"], "1");
    }

    #[test]
    fn fuzz_reflective_integers_are_decimal_strings_outside_packet_v1() {
        let value = FuzzFieldValue::from(crate::packet::internal::FieldValue::List(vec![
            crate::packet::internal::FieldValue::Unsigned(u64::MAX),
            crate::packet::internal::FieldValue::Signed(i64::MIN),
        ]));
        let value = serde_json::to_value(value).unwrap();

        assert_eq!(value["type"], "list");
        assert_eq!(value["value"][0]["value"], u64::MAX.to_string());
        assert_eq!(value["value"][1]["value"], i64::MIN.to_string());
    }
}
