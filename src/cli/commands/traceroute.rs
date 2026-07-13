// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Traceroute command execution and presentation.

fn run_traceroute(arguments: TracerouteArgs, output: OutputFormat) -> Result<(), CliError> {
    let TracerouteArgs {
        target,
        strategy,
        family,
        port,
        first_hop,
        max_hops,
        attempts,
        timeout_ms,
        rate,
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
    let strategy: TracerouteStrategy = strategy.into();
    let destination_port = match strategy {
        TracerouteStrategy::Udp => {
            Some(port.unwrap_or(crate::workflow_api::DEFAULT_TRACEROUTE_UDP_PORT))
        }
        TracerouteStrategy::Tcp => {
            Some(port.unwrap_or(crate::workflow_api::DEFAULT_TRACEROUTE_TCP_PORT))
        }
        TracerouteStrategy::Icmp => port,
    };
    let capture_options = limits.capture_options();
    let evidence_bytes = limits.evidence_bytes();
    let queue_limits = limits.into_limits();
    let trace_limits = TracerouteLimits {
        max_probes,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: evidence_bytes,
        max_undecoded,
    };
    let request = TracerouteRequest {
        target,
        strategy,
        address_family: family.into(),
        destination_port,
        first_hop,
        max_hops,
        probes_per_hop: attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: trace_limits,
    };
    request.validate().map_err(traceroute_cli_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_live_interface_selector("traceroute", interface.as_deref())?;
    let max_template_packets = usize::try_from(attempts).map_err(|_| {
        CliError::new(2, "traceroute attempt count exceeds the platform size limit")
    })?;

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
        max_template_packets,
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

    let mut executor = CliTracerouteExecutor {
        registry: Arc::clone(&registry),
        policy: policy.clone(),
        exchange,
        capture_options,
        interface: DeferredInterface::new(interface),
    };
    let resolver = SystemHostnameResolver;
    let mut authorizer = TrafficPolicyTracerouteAuthorizer::new(&policy, &resolver);
    let mut clock = SystemClock;
    let stream_target = request.target.to_string();
    let stream_enabled = output == OutputFormat::Ndjson;
    let mut stream_sequence = 0_u64;
    let mut sink = |event: TracerouteEvent| {
        if !stream_enabled {
            return Ok(());
        }
        let destination = event
            .hop
            .probes
            .first()
            .map(|probe| probe.destination)
            .ok_or_else(|| crate::operation::EventError::new("traceroute emitted an empty hop"))?;
        let hop = TraceHopOutput::try_from_hop(event.hop)
            .map_err(|source| crate::operation::EventError::new(source.to_string()))?;
        emit_json_compact(&StreamRecord::success(
            CommandName::Traceroute,
            stream_sequence,
            TracerouteStreamCommandResult::Hop {
                target: stream_target.clone(),
                destination,
                hop,
            },
            Vec::new(),
        ))
        .map_err(|source| crate::operation::EventError::new(source.message))?;
        stream_sequence = stream_sequence.checked_add(1).ok_or_else(|| {
            crate::operation::EventError::new("traceroute output sequence overflowed")
        })?;
        for evidence in event.undecoded {
            let evidence = TraceUndecodedOutput::try_from_evidence(evidence)
                .map_err(|source| crate::operation::EventError::new(source.to_string()))?;
            emit_json_compact(&StreamRecord::success(
                CommandName::Traceroute,
                stream_sequence,
                TracerouteStreamCommandResult::Undecoded {
                    hop_limit: evidence.hop_limit,
                    frame: evidence.frame,
                },
                Vec::new(),
            ))
            .map_err(|source| crate::operation::EventError::new(source.message))?;
            stream_sequence = stream_sequence.checked_add(1).ok_or_else(|| {
                crate::operation::EventError::new("traceroute output sequence overflowed")
            })?;
        }
        Ok(())
    };
    let result = traceroute_streaming(
        &request,
        current_operation(),
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
        &mut sink,
    )
    .map_err(traceroute_cli_error)?;
    let (result, diagnostics, stats) =
        TracerouteCommandResult::try_from_traceroute(result).map_err(CliError::classified)?;

    match output {
        OutputFormat::Text => render_traceroute_text(result, diagnostics, stats),
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Traceroute, result, diagnostics)
                .with_stats(stats),
        ),
        OutputFormat::Ndjson => {
            let completion_reason = traceroute_completion_reason(result.completion);
            emit_json_compact(
                &StreamRecord::success(
                    CommandName::Traceroute,
                    stream_sequence,
                    TracerouteStreamCommandResult::Complete {
                        target: result.target,
                        resolved_addresses: result.resolved_addresses,
                        destination: result.destination,
                        strategy: result.strategy,
                        destination_port: result.destination_port,
                        completion: result.completion,
                    },
                    diagnostics,
                )
                .complete(completion_reason)
                .with_stats(stats),
            )
            .map_err(|error| error.at_sequence(stream_sequence))
        }
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Traceroute,
                format: output,
            },
        )),
    }
}

fn traceroute_completion_reason(completion: TraceCompletionReason) -> CompletionReason {
    match completion {
        TraceCompletionReason::DestinationReached => CompletionReason::DestinationReached,
        TraceCompletionReason::Timeout => CompletionReason::Timeout,
        TraceCompletionReason::Unreachable => CompletionReason::Completed,
        TraceCompletionReason::MaximumHops => CompletionReason::LimitReached,
    }
}

struct CliTracerouteExecutor {
    registry: Arc<crate::packet::internal::ProtocolRegistry>,
    policy: TrafficPolicy,
    exchange: ExchangeOptions,
    capture_options: CaptureOptions,
    interface: DeferredInterface,
}

impl TracerouteExecutor for CliTracerouteExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, TracerouteExecutionError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(|error| {
                TracerouteExecutionError::new(error.message, error.classification, error.causes)
            })?;
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        ClientTracerouteExecutor::new(&client, self.exchange.clone())
            .with_capture_options(self.capture_options.clone())
            .with_operation_context(current_operation().clone())
            .execute(batch)
    }
}

fn traceroute_cli_error(error: TracerouteError) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}

fn render_traceroute_text(
    result: TracerouteCommandResult,
    diagnostics: Vec<crate::packet::internal::Diagnostic>,
    stats: crate::output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolved={} destination={} strategy={} port={}",
        result.target,
        result
            .resolved_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        result.destination,
        result.strategy,
        result
            .destination_port
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned()),
    ))?;
    for hop in &result.hops {
        write_stdout_line(format_args!("hop={}", hop.hop_limit))?;
        for probe in &hop.probes {
            write_stdout_line(format_args!(
                "  sequence={} attempt={} status={} response={} sent={} received={} responder={} latency={} port={} reason={}",
                probe.sequence,
                probe.attempt,
                trace_probe_status_name(probe.status),
                probe
                    .response_kind
                    .map(trace_response_kind_name)
                    .unwrap_or("none"),
                output_timestamp_text(probe.sent_at),
                probe
                    .received_at
                    .map(output_timestamp_text)
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .responder
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .latency
                    .map(|value| format!("{value:?}"))
                    .unwrap_or_else(|| "none".to_owned()),
                probe
                    .destination_port
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                probe.reason,
            ))?;
            if let Some(frame) = &probe.frame {
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
    for evidence in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded hop={} dlt={} caplen={} wirelen={} {}",
            evidence.hop_limit,
            evidence.frame.link_type,
            evidence.frame.captured_length,
            evidence.frame.original_length,
            spaced_hex(evidence.frame.bytes())
        ))?;
    }
    write_stdout_line(format_args!(
        "trace completion={} hops={} probes={} bytes={}",
        trace_completion_name(result.completion),
        result.hops.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn trace_probe_status_name(value: TraceProbeStatus) -> &'static str {
    match value {
        TraceProbeStatus::Response => "response",
        TraceProbeStatus::Timeout => "timeout",
    }
}

fn trace_response_kind_name(value: TraceResponseKind) -> &'static str {
    match value {
        TraceResponseKind::Intermediate => "intermediate",
        TraceResponseKind::DestinationReached => "destination_reached",
        TraceResponseKind::Unreachable => "unreachable",
    }
}

fn trace_completion_name(value: TraceCompletionReason) -> &'static str {
    match value {
        TraceCompletionReason::DestinationReached => "destination_reached",
        TraceCompletionReason::Unreachable => "unreachable",
        TraceCompletionReason::MaximumHops => "maximum_hops",
        TraceCompletionReason::Timeout => "timeout",
    }
}
