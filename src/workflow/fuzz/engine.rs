/// Generate, build, and dissect deterministic cases without any live seam.
pub fn fuzz(
    request: &FuzzRequest,
    packet: Packet,
    registry: Arc<ProtocolRegistry>,
) -> Result<FuzzResult, FuzzError> {
    let operation = crate::operation::Context::generate().map_err(|source| {
        FuzzError::Operation {
            case_index: request.first_case,
            source,
        }
    })?;
    fuzz_streaming(request, packet, registry, &operation, &mut |_| Ok(()))
}

/// Streaming offline fuzz entry point emitting each deterministic case.
pub fn fuzz_streaming<S>(
    request: &FuzzRequest,
    packet: Packet,
    registry: Arc<ProtocolRegistry>,
    operation: &crate::operation::Context,
    sink: &mut S,
) -> Result<FuzzResult, FuzzError>
where
    S: crate::operation::EventSink<FuzzEvent>,
{
    operation
        .cancellation()
        .check()
        .map_err(|source| FuzzError::Operation {
            case_index: request.first_case,
            source,
        })?;
    let prepared = prepare(
        request,
        packet,
        registry,
        operation.cancellation(),
        |case, stats| {
            sink.emit(FuzzEvent {
                case: case.clone(),
                stats,
            })
            .map_err(|source| FuzzError::Event {
                case_index: case.index,
                source,
            })
        },
    )?;
    let result = FuzzResult {
        mode: FuzzMode::Offline,
        seed: request.seed,
        first_case: request.first_case,
        cases: prepared.cases,
        diagnostics: Vec::new(),
        stats: FuzzStats {
            cases_generated: request.cases as u64,
            cases_built: prepared.built_case_count,
            cases_rejected: request.cases as u64 - prepared.built_case_count,
            packets_attempted: request.cases as u64,
            packets_completed: prepared.built_case_count,
            bytes: prepared.built_byte_count,
            ..FuzzStats::default()
        },
    };
    Ok(result)
}

/// Generate and validate every case offline, authorize the complete campaign,
/// then execute built cases through the shared live boundary.
pub fn fuzz_live<A, E, C>(
    request: &FuzzRequest,
    live: FuzzLiveOptions,
    packet: Packet,
    registry: Arc<ProtocolRegistry>,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
) -> Result<FuzzResult, FuzzError>
where
    A: FuzzAuthorizer,
    E: FuzzExecutor,
    C: Clock,
{
    let operation = crate::operation::Context::generate().map_err(|source| {
        FuzzError::Operation {
            case_index: request.first_case,
            source,
        }
    })?;
    fuzz_live_streaming(
        request,
        live,
        packet,
        registry,
        &operation,
        authorizer,
        executor,
        clock,
        &mut |_| Ok(()),
    )
}

/// Streaming live fuzz entry point emitting each case after execution.
// The live adapters are deliberately separate public seams so callers can
// supply policy, execution, time, cancellation, and output independently.
#[allow(clippy::too_many_arguments)]
pub fn fuzz_live_streaming<A, E, C, S>(
    request: &FuzzRequest,
    live: FuzzLiveOptions,
    packet: Packet,
    registry: Arc<ProtocolRegistry>,
    operation: &crate::operation::Context,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
    sink: &mut S,
) -> Result<FuzzResult, FuzzError>
where
    A: FuzzAuthorizer,
    E: FuzzExecutor,
    C: Clock,
    S: crate::operation::EventSink<FuzzEvent>,
{
    operation
        .cancellation()
        .check()
        .map_err(|source| FuzzError::Operation {
            case_index: request.first_case,
            source,
        })?;
    let live = live.validate()?;
    let operation_started = Instant::now();
    let live_dissector = Dissector::new(Arc::clone(&registry));
    let mut prepared = prepare(
        request,
        packet,
        registry,
        operation.cancellation(),
        |_, _| Ok(()),
    )?;
    let built_indices = prepared
        .cases
        .iter()
        .enumerate()
        .filter_map(|(index, case)| case.built.is_some().then_some(index))
        .collect::<Vec<_>>();

    let worst_case = worst_case_duration(live, built_indices.len())?;
    let complete_worst_case =
        prepared
            .preparation_elapsed
            .checked_add(worst_case)
            .ok_or(FuzzError::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
    if complete_worst_case > request.limits.max_duration {
        return Err(FuzzError::DurationLimit {
            actual: complete_worst_case,
            limit: request.limits.max_duration,
        });
    }

    let maximum_wire_bytes = prepared.cases.iter().try_fold(0_u64, |total, case| {
        let Some(built) = &case.built else {
            return Ok(total);
        };
        let overhead = if has_link_root(&built.packet) {
            0
        } else {
            SYNTHESIZED_ETHERNET_BYTES
        };
        total
            .checked_add(built.bytes.len() as u64)
            .and_then(|value| value.checked_add(overhead))
            .ok_or(FuzzError::ByteLimit {
                actual: u64::MAX,
                limit: request.limits.max_total_bytes as u64,
            })
    })?;
    if maximum_wire_bytes > request.limits.max_total_bytes as u64 {
        return Err(FuzzError::ByteLimit {
            actual: maximum_wire_bytes,
            limit: request.limits.max_total_bytes as u64,
        });
    }
    let requires_malformed_live = prepared.cases.iter().any(|case| {
        case.built
            .as_ref()
            .is_some_and(|built| built.requires_live_opt_in)
    });
    if requires_malformed_live && !live.allow_malformed_live {
        return Err(FuzzError::MalformedLiveOptInRequired);
    }
    let packets = built_indices
        .iter()
        .map(|index| {
            prepared.cases[*index]
                .built
                .as_ref()
                .expect("selected built case")
                .packet
                .clone()
        })
        .collect::<Vec<_>>();
    if !packets.is_empty() {
        authorizer.authorize_operation(
            &packets,
            live.destination,
            maximum_wire_bytes,
            requires_malformed_live,
        )?;
    }
    enforce_operation_deadline(
        operation_started,
        prepared.preparation_elapsed,
        request.limits.max_duration,
    )?;

    let mut stats = FuzzStats {
        cases_generated: request.cases as u64,
        cases_built: prepared.built_case_count,
        cases_rejected: request.cases as u64 - prepared.built_case_count,
        ..FuzzStats::default()
    };
    let mut evidence = EvidenceBudget::default();
    let mut operation_diagnostics = Vec::new();
    let mut scheduled_delay = Duration::ZERO;
    for case in prepared.cases.iter().filter(|case| case.built.is_none()) {
        sink.emit(FuzzEvent {
            case: case.clone(),
            stats: stats.clone(),
        })
        .map_err(|source| FuzzError::Event {
            case_index: case.index,
            source,
        })?;
    }
    for (ordinal, case_index) in built_indices.into_iter().enumerate() {
        let case = &mut prepared.cases[case_index];
        operation
            .cancellation()
            .check()
            .map_err(|source| FuzzError::Operation {
                case_index: case.index,
                source,
            })?;
        if ordinal != 0 {
            let delay = rate_delay(live.cases_per_second)?;
            match clock.sleep_cancelled(delay, operation.cancellation()) {
                Ok(()) => {}
                Err(super::clock::SleepError::Clock(source)) => {
                    return Err(FuzzError::Clock {
                        case_index: case.index,
                        message: source.to_string(),
                    });
                }
                Err(super::clock::SleepError::Cancelled(source)) => {
                    return Err(FuzzError::Operation {
                        case_index: case.index,
                        source,
                    });
                }
            }
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(FuzzError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
        }
        let accounted_elapsed = prepared
            .preparation_elapsed
            .checked_add(stats.elapsed)
            .and_then(|value| value.checked_add(scheduled_delay))
            .ok_or(FuzzError::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
        enforce_operation_deadline(
            operation_started,
            accounted_elapsed,
            request.limits.max_duration,
        )?;
        let execution_case = FuzzExecutionCase {
            index: case.index,
            seed: case.seed,
            packet: case.recipe.clone(),
        };
        let execution = executor
            .execute(&execution_case, live.timeout)
            .map_err(|source| FuzzError::Execution {
                case_index: case.index,
                source,
            })?;
        validate_execution(case, &execution, request.limits, live.timeout)?;
        add_execution_stats(&mut stats, &execution.stats, case.index)?;
        if stats.bytes > request.limits.max_total_bytes as u64 {
            return Err(FuzzError::ByteLimit {
                actual: stats.bytes,
                limit: request.limits.max_total_bytes as u64,
            });
        }
        let accounted_elapsed = prepared
            .preparation_elapsed
            .checked_add(stats.elapsed)
            .and_then(|value| value.checked_add(scheduled_delay))
            .ok_or(FuzzError::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
        enforce_operation_deadline(
            operation_started,
            accounted_elapsed,
            request.limits.max_duration,
        )?;
        let had_response = !execution.responses.is_empty();
        case.diagnostics = execution.built.diagnostics.clone();
        case.decoded = dissect_built(
            &live_dissector,
            &execution.built,
            request.limits,
            &mut case.diagnostics,
        );
        case.built = Some(execution.built);
        case.sent = Some(execution.sent);
        case.diagnostics.extend(execution.diagnostics);
        retain_evidence(
            case,
            execution.responses,
            execution.unmatched,
            execution.undecoded,
            request.limits,
            &mut evidence,
            &mut operation_diagnostics,
        );
        case.outcome = if had_response {
            FuzzCaseOutcome::Response
        } else {
            FuzzCaseOutcome::Timeout
        };
        sink.emit(FuzzEvent {
            case: case.clone(),
            stats: stats.clone(),
        })
        .map_err(|source| FuzzError::Event {
            case_index: case.index,
            source,
        })?;
    }
    stats.elapsed =
        stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(FuzzError::StatisticsOverflow {
                case_index: request
                    .first_case
                    .saturating_add(request.cases.saturating_sub(1) as u64),
            })?;

    Ok(FuzzResult {
        mode: FuzzMode::Live,
        seed: request.seed,
        first_case: request.first_case,
        cases: prepared.cases,
        diagnostics: operation_diagnostics,
        stats,
    })
}

struct PreparedFuzz {
    cases: Vec<FuzzCase>,
    built_case_count: u64,
    built_byte_count: u64,
    preparation_elapsed: Duration,
}

#[derive(Clone)]
struct ResolvedField {
    target: FuzzTarget,
    protocol: String,
    kind: FieldKind,
    is_derived: bool,
}
