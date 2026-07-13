// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Scan command execution and presentation.

fn run_scan(arguments: ScanArgs, output: OutputFormat) -> Result<(), CliError> {
    let ScanArgs {
        target,
        transport,
        family,
        ports,
        attempts,
        timeout_ms,
        rate,
        batch_size,
        max_ports,
        max_probes,
        max_duration_ms,
        max_undecoded,
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let target = match target.parse::<LiveTarget>().map_err(CliError::classified)? {
        LiveTarget::Address(address) => ScanTarget::Address(address),
        LiveTarget::Hostname(hostname) => ScanTarget::Hostname(hostname.to_string()),
    };
    let capture_options = limits.capture_options();
    let evidence_bytes = limits.evidence_bytes();
    let queue_limits = limits.into_limits();
    let scan_limits = ScanLimits {
        max_ports,
        max_probes,
        batch_size,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: evidence_bytes,
        max_undecoded,
    };
    scan_limits.validate().map_err(scan_cli_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_live_interface_selector("scan", interface.as_deref())?;
    let request = ScanRequest {
        target,
        transport: transport.into(),
        address_family: family.into(),
        ports,
        attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: scan_limits,
    };
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
        max_template_packets: batch_size,
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

    let mut executor = CliScanExecutor {
        registry: Arc::clone(&registry),
        policy: policy.clone(),
        exchange,
        capture_options,
        interface: DeferredInterface::new(interface),
    };
    let resolver = SystemHostnameResolver;
    let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);
    let mut clock = SystemClock;
    let stream_target = request.target.to_string();
    let stream_enabled = output == OutputFormat::Ndjson;
    let mut stream_sequence = 0_u64;
    let mut sink = |event: ScanEvent| {
        if !stream_enabled {
            return Ok(());
        }
        for endpoint in event.endpoints {
            let resolved_address = endpoint.address;
            let port = ScanPortOutput::try_from_endpoint(endpoint)
                .map_err(|source| crate::operation::EventError::new(source.to_string()))?;
            emit_json_compact(&StreamRecord::success(
                CommandName::Scan,
                stream_sequence,
                ScanStreamCommandResult::Port {
                    target: stream_target.clone(),
                    resolved_address,
                    port,
                },
                Vec::new(),
            ))
            .map_err(|source| crate::operation::EventError::new(source.message))?;
            stream_sequence = stream_sequence.checked_add(1).ok_or_else(|| {
                crate::operation::EventError::new("scan output sequence overflowed")
            })?;
        }
        for evidence in event.undecoded {
            let frame = FrameOutput::try_from_frame(evidence)
                .map_err(|source| crate::operation::EventError::new(source.to_string()))?;
            emit_json_compact(&StreamRecord::success(
                CommandName::Scan,
                stream_sequence,
                ScanStreamCommandResult::Undecoded { frame },
                Vec::new(),
            ))
            .map_err(|source| crate::operation::EventError::new(source.message))?;
            stream_sequence = stream_sequence.checked_add(1).ok_or_else(|| {
                crate::operation::EventError::new("scan output sequence overflowed")
            })?;
        }
        Ok(())
    };
    let result = scan_streaming(
        &request,
        current_operation(),
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
        &mut sink,
    )
    .map_err(scan_cli_error)?;
    let (result, diagnostics, stats) =
        ScanCommandResult::try_from_scan(result).map_err(CliError::classified)?;

    match output {
        OutputFormat::Text => render_scan_text(result, diagnostics, stats),
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Scan, result, diagnostics).with_stats(stats),
        ),
        OutputFormat::Ndjson => emit_json_compact(
            &StreamRecord::success(
                CommandName::Scan,
                stream_sequence,
                ScanStreamCommandResult::Complete {
                    target: result.target,
                    resolved_addresses: result.resolved_addresses,
                },
                diagnostics,
            )
            .complete(CompletionReason::Completed)
            .with_stats(stats),
        )
        .map_err(|error| error.at_sequence(stream_sequence)),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Scan,
                format: output,
            },
        )),
    }
}

fn validate_live_interface_selector(command: &str, selector: Option<&str>) -> Result<(), CliError> {
    validate_interface_selector(command, selector).map(|_| ())
}

struct CliScanExecutor {
    registry: Arc<crate::packet::internal::ProtocolRegistry>,
    policy: TrafficPolicy,
    exchange: ExchangeOptions,
    capture_options: CaptureOptions,
    interface: DeferredInterface,
}

impl ScanExecutor for CliScanExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(|error| {
                ScanExecutionError::new(error.message, error.classification, error.causes)
            })?;
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        ClientScanExecutor::new(&client, self.exchange.clone())
            .with_capture_options(self.capture_options.clone())
            .with_operation_context(current_operation().clone())
            .execute(batch)
    }
}

fn scan_cli_error(error: ScanError) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}

fn render_scan_text(
    result: ScanCommandResult,
    diagnostics: Vec<crate::packet::internal::Diagnostic>,
    stats: crate::output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolved={}",
        result.target,
        result
            .resolved_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    ))?;
    for port in &result.ports {
        let destination = port
            .evidence
            .first()
            .map(|evidence| evidence.destination)
            .ok_or_else(|| CliError::new(70, "scan endpoint has no attempt evidence"))?;
        let endpoint = if port.transport == "icmp" {
            "icmp".to_owned()
        } else {
            format!("{}/{}", port.transport, port.port)
        };
        write_stdout_line(format_args!(
            "{} {} classification={}",
            destination,
            endpoint,
            scan_classification_name(port.classification)
        ))?;
        for evidence in &port.evidence {
            write_stdout_line(format_args!(
                "  attempt={} status={} classification={} sent={} received={} responder={} latency={} reason={}",
                evidence.attempt,
                scan_probe_status_name(evidence.status),
                scan_classification_name(evidence.classification),
                output_timestamp_text(evidence.sent_at),
                evidence
                    .received_at
                    .map(output_timestamp_text)
                    .unwrap_or_else(|| "none".to_owned()),
                evidence
                    .responder
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                evidence
                    .latency
                    .map(|value| format!("{value:?}"))
                    .unwrap_or_else(|| "none".to_owned()),
                evidence.reason,
            ))?;
            if let Some(frame) = &evidence.frame {
                write_stdout_line(format_args!(
                    "    frame dlt={} caplen={} wirelen={} {}",
                    frame.link_type,
                    frame.captured_length,
                    frame.original_length,
                    spaced_hex(frame.bytes())
                ))?;
            }
        }
    }
    for frame in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded dlt={} caplen={} wirelen={} {}",
            frame.link_type,
            frame.captured_length,
            frame.original_length,
            spaced_hex(frame.bytes())
        ))?;
    }
    write_stdout_line(format_args!(
        "scanned {} endpoint(s) with {} completed probe(s), {} byte(s)",
        result.ports.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn scan_classification_name(value: crate::output::scan::Classification) -> &'static str {
    match value {
        crate::output::scan::Classification::Open => "open",
        crate::output::scan::Classification::Closed => "closed",
        crate::output::scan::Classification::Filtered => "filtered",
        crate::output::scan::Classification::Unreachable => "unreachable",
        crate::output::scan::Classification::Unknown => "unknown",
        crate::output::scan::Classification::Timeout => "timeout",
    }
}

fn scan_probe_status_name(value: crate::output::scan::ProbeStatus) -> &'static str {
    match value {
        crate::output::scan::ProbeStatus::Response => "response",
        crate::output::scan::ProbeStatus::Timeout => "timeout",
    }
}
