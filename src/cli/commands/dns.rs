// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// DNS command execution and presentation.

fn run_dns(arguments: DnsArgs, output: OutputFormat) -> Result<(), CliError> {
    let DnsArgs {
        server,
        name,
        query_type,
        family,
        port,
        transaction_id,
        source_port,
        no_recursion,
        attempts,
        timeout_ms,
        rate,
        max_duration_ms,
        max_message_bytes,
        max_records,
        max_name_pointers,
        max_txt_strings,
        max_txt_bytes,
        max_rejected_records,
        max_undecoded,
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let server = match server.parse::<LiveTarget>().map_err(CliError::classified)? {
        LiveTarget::Address(address) => ScanTarget::Address(address),
        LiveTarget::Hostname(hostname) => ScanTarget::Hostname(hostname.to_string()),
    };
    let address_family: AddressFamily = family.into();
    let port_family = dns_port_family(address_family, &server);
    let capture_options = limits.capture_options();
    let evidence_bytes = limits.evidence_bytes();
    let queue_limits = limits.into_limits();
    let generated_source_port = if source_port.is_none() {
        Some(
            current_operation()
                .reserve_port_for_family(
                    "dns.udp.source_port",
                    crate::operation::Transport::Udp,
                    port_family,
                )
                .map_err(CliError::classified)?,
        )
    } else {
        None
    };
    let request = DnsRequest {
        server,
        address_family,
        server_port: port,
        source_port: source_port
            .or(generated_source_port)
            .expect("explicit or generated port"),
        query_name: name,
        query_type: query_type.into(),
        transaction_id: transaction_id.unwrap_or_else(|| {
            current_operation()
                .id()
                .derive_u16("dns.transaction_id", 0)
        }),
        recursion_desired: !no_recursion,
        attempts,
        timeout: Duration::from_millis(timeout_ms),
        queries_per_second: rate,
        limits: DnsLimits {
            max_message_bytes,
            max_records,
            max_name_pointers,
            max_txt_strings,
            max_txt_bytes,
            max_rejected_records,
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: evidence_bytes,
            max_undecoded,
            max_duration: Duration::from_millis(max_duration_ms),
        },
    };
    request.validate().map_err(dns_cli_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_live_interface_selector("dns", interface.as_deref())?;

    let registry = default_registry_arc()?;
    let mut exchange = ExchangeOptions {
        send: SendOptions {
            destination: None,
            plan: crate::net::PlanOptions {
                link_mode: link_mode.into(),
                interface: None,
                preferred_source: source,
            },
            build: BuildOptions::default(),
            allow_permissive_live: false,
        },
        timeout: request.timeout,
        max_template_packets: 1,
        max_unsolicited: queue_limits.max_frames,
        max_responses: queue_limits.max_frames,
        max_capture_queue_frames: queue_limits.max_frames,
        max_captured_bytes: queue_limits.max_bytes,
        max_evidence_bytes: evidence_bytes,
        capture_overflow_policy: queue_limits.overflow_policy,
        decode: DecodeOptions::default(),
    };
    exchange.decode.max_packet_size = queue_limits.snap_length;
    exchange.validate().map_err(CliError::classified)?;

    let mut executor = CliDnsExecutor {
        registry: Arc::clone(&registry),
        policy: policy.clone(),
        exchange,
        capture_options,
        interface: DeferredInterface::new(interface),
    };
    let resolver = SystemHostnameResolver;
    let mut authorizer = TrafficPolicyDnsAuthorizer::new(&policy, &resolver);
    let mut clock = SystemClock;
    let stream_server = request.server.to_string();
    let stream_server_port = request.server_port;
    let stream_query_name = request.query_name.clone();
    let stream_query_type = request.query_type.to_string();
    let stream_enabled = output == OutputFormat::Ndjson;
    let mut stream_sequence = 0_u64;
    let mut sink = |event: DnsEvent| {
        if !stream_enabled {
            return Ok(());
        }
        let evidence = DnsAttemptOutput::try_from_evidence(event.attempt)
            .map_err(|source| crate::operation::EventError::new(source.to_string()))?;
        emit_json_compact(&StreamRecord::success(
            CommandName::Dns,
            stream_sequence,
            DnsStreamCommandResult::Attempt {
                server: stream_server.clone(),
                server_port: stream_server_port,
                query_name: stream_query_name.clone(),
                query_type: stream_query_type.clone(),
                evidence,
            },
            Vec::new(),
        ))
        .map_err(|source| crate::operation::EventError::new(source.message))?;
        stream_sequence = stream_sequence.checked_add(1).ok_or_else(|| {
            crate::operation::EventError::new("DNS output sequence overflowed")
        })?;
        for evidence in event.undecoded {
            let evidence = DnsUndecodedOutput::try_from_evidence(evidence)
                .map_err(|source| crate::operation::EventError::new(source.to_string()))?;
            emit_json_compact(&StreamRecord::success(
                CommandName::Dns,
                stream_sequence,
                DnsStreamCommandResult::Undecoded { evidence },
                Vec::new(),
            ))
            .map_err(|source| crate::operation::EventError::new(source.message))?;
            stream_sequence = stream_sequence.checked_add(1).ok_or_else(|| {
                crate::operation::EventError::new("DNS output sequence overflowed")
            })?;
        }
        Ok(())
    };
    let result = dns_streaming(
        &request,
        current_operation(),
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
        &mut sink,
    )
    .map_err(dns_cli_error)?;
    let (result, diagnostics, stats) =
        DnsCommandResult::try_from_dns(result).map_err(CliError::classified)?;
    match output {
        OutputFormat::Text => render_dns_text(result, diagnostics, stats),
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Dns, result, diagnostics).with_stats(stats),
        ),
        OutputFormat::Ndjson => {
            let mut result = result;
            result.attempts.clear();
            result.undecoded.clear();
            render_dns_stream(result, diagnostics, stats, stream_sequence)
        }
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Dns,
                format: output,
            },
        )),
    }
}

fn dns_port_family(
    address_family: AddressFamily,
    server: &ScanTarget,
) -> crate::operation::PortFamily {
    match (address_family, server) {
        (AddressFamily::Any, ScanTarget::Address(address)) if address.is_ipv4() => {
            crate::operation::PortFamily::Ipv4
        }
        (AddressFamily::Any, ScanTarget::Address(_)) => crate::operation::PortFamily::Ipv6,
        (AddressFamily::Any, ScanTarget::Hostname(_)) => crate::operation::PortFamily::Both,
        (AddressFamily::Ipv4, _) => crate::operation::PortFamily::Ipv4,
        (AddressFamily::Ipv6, _) => crate::operation::PortFamily::Ipv6,
    }
}

struct CliDnsExecutor {
    registry: Arc<crate::packet::internal::ProtocolRegistry>,
    policy: TrafficPolicy,
    exchange: ExchangeOptions,
    capture_options: CaptureOptions,
    interface: DeferredInterface,
}

impl DnsExecutor for CliDnsExecutor {
    fn execute(
        &mut self,
        exchange: &DnsExchange,
    ) -> Result<DnsExchangeExecution, DnsExecutionError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(|error| {
                DnsExecutionError::new(error.message, error.classification, error.causes)
            })?;
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        ClientDnsExecutor::new(&client, self.exchange.clone())
            .with_capture_options(self.capture_options.clone())
            .with_operation_context(current_operation().clone())
            .execute(exchange)
    }
}

fn dns_cli_error(error: DnsError) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}

fn render_dns_text(
    result: DnsCommandResult,
    diagnostics: Vec<crate::packet::internal::Diagnostic>,
    stats: crate::output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "server={}:{} resolved={} query={} type={} id={} transport={} outcome={}",
        result.server,
        result.server_port,
        result
            .resolved_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        result.query_name,
        result.query_type,
        result.transaction_id,
        result.transport,
        dns_outcome_name(result.outcome),
    ))?;
    for attempt in &result.attempts {
        write_stdout_line(format_args!(
            "attempt={} server={} source_port={} status={} sent={} received={} latency={} rcode={} reason={}",
            attempt.attempt,
            attempt.server_address,
            attempt.source_port,
            dns_attempt_status_name(attempt.status),
            output_timestamp_text(attempt.sent_at),
            attempt
                .received_at
                .map(output_timestamp_text)
                .unwrap_or_else(|| "none".to_owned()),
            attempt
                .latency
                .map(|value| format!("{value:?}"))
                .unwrap_or_else(|| "none".to_owned()),
            attempt
                .response_code
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_owned()),
            attempt.reason,
        ))?;
        if let Some(frame) = &attempt.frame {
            write_stdout_line(format_args!(
                "  frame dlt={} caplen={} wirelen={} {}",
                frame.link_type,
                frame.captured_length,
                frame.original_length,
                spaced_hex(frame.bytes())
            ))?;
        }
    }
    for (section, records) in [
        (DnsSection::Answer, &result.answers),
        (DnsSection::Authority, &result.authorities),
        (DnsSection::Additional, &result.additionals),
    ] {
        for record in records {
            render_dns_record_text(section, record)?;
        }
    }
    for record in &result.rejected_records {
        write_stdout_line(format_args!(
            "rejected section={} index={} owner={} type_code={} reason={}",
            dns_section_name(record.section),
            record.index,
            record.owner,
            record.type_code,
            record.reason,
        ))?;
    }
    for evidence in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded attempt={} dlt={} caplen={} wirelen={} {}",
            evidence.attempt,
            evidence.frame.link_type,
            evidence.frame.captured_length,
            evidence.frame.original_length,
            spaced_hex(evidence.frame.bytes())
        ))?;
    }
    write_stdout_line(format_args!(
        "dns response_code={} response_name={} authoritative={} truncated={} accepted={} rejected={} queries={} bytes={}",
        result
            .response_code
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
        result.response_code_name.as_deref().unwrap_or("none"),
        result
            .authoritative
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
        result
            .truncated
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
        result.answers.len() + result.authorities.len() + result.additionals.len(),
        result.rejected_record_count,
        stats.packets_completed,
        stats.bytes,
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn render_dns_record_text(section: DnsSection, record: &DnsRecordOutput) -> Result<(), CliError> {
    let data = serde_json::to_string(&record.data)
        .map_err(|error| CliError::new(4, format!("DNS output serialization failed: {error}")))?;
    write_stdout_line(format_args!(
        "record section={} owner={} class={} ttl={} data={}",
        dns_section_name(section),
        record.owner,
        record.class,
        record.ttl,
        data,
    ))
}

fn render_dns_stream(
    result: DnsCommandResult,
    diagnostics: Vec<crate::packet::internal::Diagnostic>,
    stats: crate::output::envelope::Stats,
    mut sequence: u64,
) -> Result<(), CliError> {
    let DnsCommandResult {
        server,
        server_port,
        resolved_addresses,
        query_name,
        query_type,
        transaction_id,
        transport,
        outcome,
        response_code,
        response_code_name,
        edns,
        authoritative,
        truncated,
        recursion_desired,
        recursion_available,
        authenticated_data,
        checking_disabled,
        answers,
        authorities,
        additionals,
        rejected_records,
        rejected_record_count,
        attempts,
        undecoded,
    } = result;
    for evidence in attempts {
        emit_dns_record(
            &mut sequence,
            DnsStreamCommandResult::Attempt {
                server: server.clone(),
                server_port,
                query_name: query_name.clone(),
                query_type: query_type.clone(),
                evidence,
            },
        )?;
    }
    for (section, records) in [
        (DnsSection::Answer, answers),
        (DnsSection::Authority, authorities),
        (DnsSection::Additional, additionals),
    ] {
        for record in records {
            emit_dns_record(
                &mut sequence,
                DnsStreamCommandResult::Record {
                    server: server.clone(),
                    server_port,
                    query_name: query_name.clone(),
                    query_type: query_type.clone(),
                    section,
                    record,
                },
            )?;
        }
    }
    for record in rejected_records {
        emit_dns_record(
            &mut sequence,
            DnsStreamCommandResult::Rejected {
                server: server.clone(),
                server_port,
                query_name: query_name.clone(),
                query_type: query_type.clone(),
                record,
            },
        )?;
    }
    for evidence in undecoded {
        emit_dns_record(
            &mut sequence,
            DnsStreamCommandResult::Undecoded { evidence },
        )?;
    }
    let terminal_reason = if outcome == DnsOutcome::Timeout {
        CompletionReason::Timeout
    } else {
        CompletionReason::Completed
    };
    emit_json_compact(
        &StreamRecord::success(
            CommandName::Dns,
            sequence,
            DnsStreamCommandResult::Complete {
                server,
                server_port,
                resolved_addresses,
                query_name,
                query_type,
                transaction_id,
                transport,
                outcome,
                response_code,
                response_code_name,
                edns,
                authoritative,
                truncated,
                recursion_desired,
                recursion_available,
                authenticated_data,
                checking_disabled,
                rejected_record_count,
            },
            diagnostics,
        )
        .complete(terminal_reason)
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

fn emit_dns_record(sequence: &mut u64, result: DnsStreamCommandResult) -> Result<(), CliError> {
    emit_json_compact(&StreamRecord::success(
        CommandName::Dns,
        *sequence,
        result,
        Vec::new(),
    ))
    .map_err(|error| error.at_sequence(*sequence))?;
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        CliError::classified(OutputContractError::SequenceOverflow).at_sequence(*sequence)
    })?;
    Ok(())
}

fn dns_attempt_status_name(value: DnsAttemptStatus) -> &'static str {
    match value {
        DnsAttemptStatus::Response => "response",
        DnsAttemptStatus::Truncated => "truncated",
        DnsAttemptStatus::Timeout => "timeout",
        DnsAttemptStatus::Unrelated => "unrelated",
        DnsAttemptStatus::DecodeFailure => "decode_failure",
        DnsAttemptStatus::NetworkFailure => "network_failure",
    }
}

fn dns_outcome_name(value: DnsOutcome) -> &'static str {
    match value {
        DnsOutcome::Response => "response",
        DnsOutcome::Truncated => "truncated",
        DnsOutcome::Timeout => "timeout",
        DnsOutcome::Unrelated => "unrelated",
        DnsOutcome::DecodeFailure => "decode_failure",
        DnsOutcome::NetworkFailure => "network_failure",
    }
}

fn dns_section_name(value: DnsSection) -> &'static str {
    match value {
        DnsSection::Answer => "answer",
        DnsSection::Authority => "authority",
        DnsSection::Additional => "additional",
    }
}
