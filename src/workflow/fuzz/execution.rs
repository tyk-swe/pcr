fn worst_case_duration(live: FuzzLiveOptions, cases: usize) -> Result<Duration, FuzzError> {
    let exchange = live
        .timeout
        .checked_mul(cases as u32)
        .ok_or(FuzzError::DurationLimit {
            actual: Duration::MAX,
            limit: MAX_FUZZ_DURATION,
        })?;
    let delay = rate_delay(live.cases_per_second)?
        .checked_mul(cases.saturating_sub(1) as u32)
        .ok_or(FuzzError::DurationLimit {
            actual: Duration::MAX,
            limit: MAX_FUZZ_DURATION,
        })?;
    exchange.checked_add(delay).ok_or(FuzzError::DurationLimit {
        actual: Duration::MAX,
        limit: MAX_FUZZ_DURATION,
    })
}

fn rate_delay(rate: Option<u32>) -> Result<Duration, FuzzError> {
    super::clock::rate_delay(1, rate).ok_or(FuzzError::InvalidLimit {
        field: "cases_per_second",
        value: u64::from(rate.unwrap_or_default()),
        reason: "rate-delay arithmetic overflowed".to_owned(),
    })
}

fn validate_execution(
    case: &FuzzCase,
    execution: &FuzzCaseExecution,
    limits: FuzzLimits,
    timeout: Duration,
) -> Result<(), FuzzError> {
    if execution.stats.packets_attempted != 1 || execution.stats.packets_completed != 1 {
        return Err(FuzzError::InvalidEvidence {
            case_index: case.index,
            message: "successful live execution must account for exactly one attempted and completed packet".to_owned(),
        });
    }
    if execution.stats.bytes != execution.sent.bytes.len() as u64
        || execution.built.bytes != execution.sent.bytes
    {
        return Err(FuzzError::InvalidEvidence {
            case_index: case.index,
            message: "sent frame, built bytes, and byte statistics disagree".to_owned(),
        });
    }
    if execution.built.bytes.len() > limits.max_packet_bytes {
        return Err(FuzzError::InvalidEvidence {
            case_index: case.index,
            message: format!(
                "executor built {} bytes, exceeding max_packet_bytes={}",
                execution.built.bytes.len(),
                limits.max_packet_bytes
            ),
        });
    }
    execution
        .sent
        .validate()
        .map_err(|source| FuzzError::InvalidEvidence {
            case_index: case.index,
            message: format!("invalid sent evidence: {source}"),
        })?;
    execution
        .stats
        .capture
        .validate()
        .map_err(|source| FuzzError::InvalidEvidence {
            case_index: case.index,
            message: format!("invalid capture statistics: {source}"),
        })?;
    for (kind, frames) in [
        ("response", &execution.responses),
        ("unmatched", &execution.unmatched),
        ("undecoded", &execution.undecoded),
    ] {
        for frame in frames {
            frame
                .validate()
                .map_err(|source| FuzzError::InvalidEvidence {
                    case_index: case.index,
                    message: format!("invalid {kind} evidence: {source}"),
                })?;
        }
    }
    for response in &execution.responses {
        let within_deadline = response
            .timestamp
            .duration_since(execution.sent.timestamp)
            .is_ok_and(|latency| latency <= timeout);
        if !within_deadline {
            return Err(FuzzError::InvalidEvidence {
                case_index: case.index,
                message: format!(
                    "response timestamp is outside the sent frame's {timeout:?} deadline"
                ),
            });
        }
    }
    Ok(())
}

fn add_execution_stats(
    total: &mut FuzzStats,
    value: &FuzzExecutionStats,
    case_index: u64,
) -> Result<(), FuzzError> {
    macro_rules! add {
        ($field:ident) => {
            total.$field = total
                .$field
                .checked_add(value.$field)
                .ok_or(FuzzError::StatisticsOverflow { case_index })?;
        };
    }
    add!(packets_attempted);
    add!(packets_completed);
    add!(bytes);
    total.elapsed = total
        .elapsed
        .checked_add(value.elapsed)
        .ok_or(FuzzError::StatisticsOverflow { case_index })?;
    macro_rules! add_capture {
        ($field:ident) => {
            total.capture.$field = total
                .capture
                .$field
                .checked_add(value.capture.$field)
                .ok_or(FuzzError::StatisticsOverflow { case_index })?;
        };
    }
    add_capture!(received_frames);
    add_capture!(received_bytes);
    add_capture!(dropped_frames);
    add_capture!(dropped_bytes);
    add_capture!(overflow_events);
    add_capture!(receiver_dropped_frames);
    Ok(())
}

#[derive(Default)]
struct EvidenceBudget {
    retained_frame_count: usize,
    retained_byte_count: usize,
}

impl EvidenceBudget {
    fn retain(&mut self, frame: &Frame, limits: FuzzLimits) -> bool {
        let Some(next_frame_count) = self.retained_frame_count.checked_add(1) else {
            return false;
        };
        let Some(next_byte_count) = self.retained_byte_count.checked_add(frame.bytes.len()) else {
            return false;
        };
        if next_frame_count > limits.max_evidence_frames
            || next_byte_count > limits.max_evidence_bytes
        {
            return false;
        }
        self.retained_frame_count = next_frame_count;
        self.retained_byte_count = next_byte_count;
        true
    }
}

#[allow(clippy::too_many_arguments)]
fn retain_evidence(
    case: &mut FuzzCase,
    responses: Vec<Frame>,
    unmatched: Vec<Frame>,
    undecoded: Vec<Frame>,
    limits: FuzzLimits,
    budget: &mut EvidenceBudget,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut omitted = false;
    for frame in responses {
        if budget.retain(&frame, limits) {
            case.responses.push(frame);
        } else {
            omitted = true;
        }
    }
    for frame in unmatched {
        if budget.retain(&frame, limits) {
            case.unmatched.push(frame);
        } else {
            omitted = true;
        }
    }
    for frame in undecoded {
        if budget.retain(&frame, limits) {
            case.undecoded.push(frame);
        } else {
            omitted = true;
        }
    }
    if omitted
        && !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "fuzz.evidence_limit")
    {
        diagnostics.push(Diagnostic::warning(
            "fuzz.evidence_limit",
            format!(
                "fuzz response evidence exceeded {} frame(s) or {} byte(s); later exact frames were omitted",
                limits.max_evidence_frames, limits.max_evidence_bytes
            ),
        ));
    }
}

fn case_seed(operation_seed: u64, case_index: u64) -> u64 {
    let mut random =
        SplitMix64::new(operation_seed ^ case_index.wrapping_mul(SPLITMIX_INCREMENT) ^ CASE_DOMAIN);
    random.next_u64()
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(SPLITMIX_INCREMENT);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        while output.len() < length {
            let bytes = self.next_u64().to_le_bytes();
            let remaining = length - output.len();
            output.extend_from_slice(&bytes[..remaining.min(bytes.len())]);
        }
        output
    }
}
