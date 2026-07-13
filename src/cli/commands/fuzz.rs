// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Fuzz command execution and presentation.

fn run_fuzz(arguments: FuzzArgs, output: OutputFormat) -> Result<(), CliError> {
    let FuzzArgs {
        recipe,
        seed,
        first_case,
        cases,
        strategies,
        fields,
        mode,
        live,
        allow_malformed_live,
        destination,
        timeout_ms,
        rate,
        max_cases,
        max_total_bytes,
        max_field_bytes,
        max_list_items,
        max_shrink_steps,
        max_duration_ms,
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let registry = default_registry_arc()?;
    let packet = read_recipe(recipe, &registry)?;
    let targets = fields
        .into_iter()
        .map(|field| {
            field
                .parse::<FuzzTarget>()
                .map_err(|source| CliError::new(2, source.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let queue_limits = limits.into_limits();
    let build_mode = match mode {
        CliBuildMode::Strict => BuildMode::Strict,
        CliBuildMode::Permissive => BuildMode::Permissive,
    };
    let request = FuzzRequest {
        seed,
        first_case,
        cases,
        strategies: strategies.into_iter().map(Into::into).collect(),
        targets,
        build: BuildOptions {
            mode: build_mode,
            max_packet_size: queue_limits.snap_length,
            ..BuildOptions::default()
        },
        limits: FuzzLimits {
            max_cases,
            max_packet_bytes: queue_limits.snap_length,
            max_total_bytes,
            max_field_bytes,
            max_list_items,
            max_shrink_steps,
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: queue_limits.max_bytes,
            max_duration: Duration::from_millis(max_duration_ms),
        },
    };
    request.validate().map_err(fuzz_cli_error)?;

    let result = if live {
        let policy = policy.into_policy();
        policy.validate().map_err(CliError::classified)?;
        validate_live_interface_selector("fuzz", interface.as_deref())?;
        let mut exchange = ExchangeOptions {
            send: SendOptions {
                destination,
                plan: crate::net::PlanOptions {
                    link_mode: link_mode.into(),
                    interface: None,
                    preferred_source: source,
                },
                build: request.build.clone(),
                allow_permissive_live: allow_malformed_live,
            },
            timeout: Duration::from_millis(timeout_ms),
            max_template_packets: 1,
            max_unsolicited: queue_limits.max_frames,
            max_responses: queue_limits.max_frames,
            max_capture_queue_frames: queue_limits.max_frames,
            max_captured_bytes: queue_limits.max_bytes,
            capture_overflow_policy: queue_limits.overflow_policy,
            decode: DecodeOptions::default(),
        };
        exchange.decode.max_packet_size = queue_limits.snap_length;
        exchange.validate().map_err(CliError::classified)?;
        let mut executor = CliFuzzExecutor {
            registry: Arc::clone(&registry),
            policy: policy.clone(),
            exchange,
            interface: DeferredInterface::new(interface),
        };
        let mut authorizer = TrafficPolicyFuzzAuthorizer::new(&policy);
        let mut clock = SystemClock;
        fuzz_live(
            &request,
            FuzzLiveOptions {
                timeout: Duration::from_millis(timeout_ms),
                cases_per_second: rate,
                destination,
                allow_malformed_live,
            },
            packet,
            registry,
            &mut authorizer,
            &mut executor,
            &mut clock,
        )
        .map_err(fuzz_cli_error)?
    } else {
        // This branch intentionally never validates or resolves the live
        // interface and never constructs a native client.
        fuzz(&request, packet, registry).map_err(fuzz_cli_error)?
    };
    let (result, diagnostics, stats) =
        FuzzCommandResult::try_from_fuzz(result).map_err(CliError::classified)?;
    match output {
        OutputFormat::Text => render_fuzz_text(result, diagnostics, stats),
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Fuzz, result, diagnostics).with_stats(stats),
        ),
        OutputFormat::Ndjson => render_fuzz_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Fuzz,
                format: output,
            },
        )),
    }
}

struct CliFuzzExecutor {
    registry: Arc<crate::packet::internal::ProtocolRegistry>,
    policy: TrafficPolicy,
    exchange: ExchangeOptions,
    interface: DeferredInterface,
}

impl FuzzExecutor for CliFuzzExecutor {
    fn execute(
        &mut self,
        case: &FuzzExecutionCase,
        timeout: Duration,
    ) -> Result<FuzzCaseExecution, FuzzExecutionError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(|error| {
                FuzzExecutionError::new(error.message, error.classification, error.causes)
            })?;
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        ClientFuzzExecutor::new(&client, self.exchange.clone()).execute(case, timeout)
    }
}

fn fuzz_cli_error(error: FuzzError) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}

fn render_fuzz_text(
    result: FuzzCommandResult,
    diagnostics: Vec<crate::packet::internal::Diagnostic>,
    stats: crate::output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "mode={} seed={} first_case={} generated={} built={} rejected={}",
        fuzz_mode_name(result.mode),
        result.seed,
        result.first_case,
        result.cases_generated,
        result.cases_built,
        result.cases_rejected,
    ))?;
    for case in &result.cases {
        write_stdout_line(format_args!(
            "case={} seed={} strategy={} target={}.{} outcome={} length={} reproduce=--seed {} --first-case {} --cases 1",
            case.index,
            case.seed,
            case.mutation.strategy,
            case.mutation.layer,
            case.mutation.field,
            fuzz_outcome_name(case.outcome),
            case.frame.as_ref().map(|frame| frame.length).unwrap_or(0),
            case.reproduction.operation_seed,
            case.reproduction.case_index,
        ))?;
        let original = serde_json::to_string(&case.mutation.original).map_err(|source| {
            CliError::new(70, format!("serialize fuzz mutation failed: {source}"))
        })?;
        let value = serde_json::to_string(&case.mutation.value).map_err(|source| {
            CliError::new(70, format!("serialize fuzz mutation failed: {source}"))
        })?;
        write_stdout_line(format_args!("  original={original} value={value}"))?;
        if let Some(frame) = &case.frame {
            write_stdout_line(format_args!("  frame {}", spaced_hex(frame.bytes())))?;
        }
        if let Some(error) = &case.error {
            write_stdout_line(format_args!(
                "  error kind={} code={} message={}",
                error.kind.as_str(),
                error.code,
                error.message,
            ))?;
        }
        if let Some(sent) = &case.sent {
            write_stdout_line(format_args!(
                "  sent dlt={} caplen={} wirelen={} {}",
                sent.link_type,
                sent.captured_length,
                sent.original_length,
                spaced_hex(sent.bytes())
            ))?;
        }
        for (kind, frames) in [
            ("response", &case.responses),
            ("unmatched", &case.unmatched),
            ("undecoded", &case.undecoded),
        ] {
            for frame in frames {
                write_stdout_line(format_args!(
                    "  {kind} dlt={} caplen={} wirelen={} {}",
                    frame.link_type,
                    frame.captured_length,
                    frame.original_length,
                    spaced_hex(frame.bytes())
                ))?;
            }
        }
        render_output_diagnostics_text(&case.diagnostics)?;
    }
    write_stdout_line(format_args!(
        "fuzz completed {} case(s), {} packet operation(s), {} byte(s)",
        result.cases_generated, stats.packets_completed, stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn render_fuzz_stream(
    result: FuzzCommandResult,
    diagnostics: Vec<crate::packet::internal::Diagnostic>,
    stats: crate::output::envelope::Stats,
) -> Result<(), CliError> {
    let FuzzCommandResult {
        seed,
        first_case,
        mode,
        cases_generated,
        cases_built,
        cases_rejected,
        cases,
    } = result;
    let mut sequence = 0_u64;
    for case in cases {
        emit_fuzz_record(
            &mut sequence,
            FuzzStreamCommandResult::Case {
                operation_seed: seed,
                case: Box::new(case),
            },
        )?;
    }
    emit_json_compact(
        &StreamRecord::success(
            CommandName::Fuzz,
            sequence,
            FuzzStreamCommandResult::Complete {
                operation_seed: seed,
                first_case,
                mode,
                cases_generated,
                cases_built,
                cases_rejected,
            },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

fn emit_fuzz_record(sequence: &mut u64, result: FuzzStreamCommandResult) -> Result<(), CliError> {
    emit_json_compact(&StreamRecord::success(
        CommandName::Fuzz,
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

fn fuzz_mode_name(value: FuzzMode) -> &'static str {
    match value {
        FuzzMode::Offline => "offline",
        FuzzMode::Live => "live",
    }
}

fn fuzz_outcome_name(value: FuzzCaseOutcome) -> &'static str {
    match value {
        FuzzCaseOutcome::Built => "built",
        FuzzCaseOutcome::Rejected => "rejected",
        FuzzCaseOutcome::Sent => "sent",
        FuzzCaseOutcome::Response => "response",
        FuzzCaseOutcome::Timeout => "timeout",
        FuzzCaseOutcome::Error => "error",
    }
}
