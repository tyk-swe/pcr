/// Validates the complete replay stream, policy, interface/mode selection,
/// timing, and aggregate budgets without delaying or transmitting.
pub fn prepare_replay<R, A, T>(
    reader: &mut Reader<R>,
    options: &ReplayOptions,
    operation: &crate::operation::Context,
    authorizer: &mut A,
    transmitter: &mut T,
) -> Result<ReplayPlan, ReplayError>
where
    R: Read,
    A: ReplayAuthorizer,
    T: ReplayTransmitter,
{
    let limits = options.limits.validate()?;
    let timing = options.timing.validate()?;
    operation
        .cancellation()
        .check()
        .map_err(|source| ReplayError::Operation {
            sequence: 0,
            source,
        })?;
    let source_format = reader.format();
    let mut previous_timestamp = None;
    let mut frames = Vec::new();
    let mut bytes = 0_u64;
    let mut scheduled_duration = Duration::ZERO;

    loop {
        let sequence = frames.len() as u64;
        operation
            .cancellation()
            .check()
            .map_err(|source| ReplayError::Operation { sequence, source })?;
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| ReplayError::Capture { sequence, source })?
        else {
            break;
        };
        let capture_interface = replay_capture_interface(reader, &frame, sequence)?;
        let next_frames = sequence.checked_add(1).ok_or(ReplayError::FrameLimit {
            sequence,
            actual: u64::MAX,
            limit: limits.max_frames,
        })?;
        if next_frames > limits.max_frames {
            return Err(ReplayError::FrameLimit {
                sequence,
                actual: next_frames,
                limit: limits.max_frames,
            });
        }
        if frame.bytes.len() > limits.max_frame_bytes {
            return Err(ReplayError::FrameSizeLimit {
                sequence,
                actual: frame.bytes.len(),
                limit: limits.max_frame_bytes,
            });
        }
        let next_bytes = bytes
            .checked_add(u64::from(frame.captured_length))
            .ok_or(ReplayError::ByteLimit {
                sequence,
                actual: u64::MAX,
                limit: limits.max_bytes,
            })?;
        if next_bytes > limits.max_bytes {
            return Err(ReplayError::ByteLimit {
                sequence,
                actual: next_bytes,
                limit: limits.max_bytes,
            });
        }
        let mode = replay_link_mode(sequence, frame.link_type, options.link_mode)?;
        let delay = match previous_timestamp {
            Some(previous) => timing.delay_between(previous, frame.timestamp).map_err(|error| {
                match error {
                    ReplayError::InvalidTiming { mode, value } => ReplayError::Timing {
                        sequence,
                        mode,
                        value,
                    },
                    error => error,
                }
            })?,
            None => Duration::ZERO,
        };
        let next_duration = scheduled_duration
            .checked_add(delay)
            .ok_or(ReplayError::DurationLimit {
                sequence,
                actual: Duration::MAX,
                limit: limits.max_duration,
            })?;
        if next_duration > limits.max_duration {
            return Err(ReplayError::DurationLimit {
                sequence,
                actual: next_duration,
                limit: limits.max_duration,
            });
        }
        authorizer
            .authorize(&frame, mode)
            .map_err(|source| ReplayError::Authorization { sequence, source })?;
        let interface = transmitter
            .validate_interface(&options.interface, mode, &frame)
            .map_err(|source| ReplayError::Transmission { sequence, source })?;
        frames.push(PreparedReplayFrame {
            identity: replay_frame_identity(&frame, capture_interface),
            source_interface_id: frame.interface,
            capture_interface,
            interface,
            mode,
            delay,
        });
        bytes = next_bytes;
        scheduled_duration = next_duration;
        previous_timestamp = Some(frame.timestamp);
    }

    Ok(ReplayPlan {
        source_format,
        timing,
        frames,
        bytes,
        scheduled_duration,
    })
}

/// Executes a prepared replay against a rewound reader, verifying each frame
/// identity immediately before its delay and transmission.
pub fn execute_replay<R, T, C, S>(
    reader: &mut Reader<R>,
    plan: &ReplayPlan,
    operation: &crate::operation::Context,
    transmitter: &mut T,
    clock: &mut C,
    sink: &mut S,
) -> Result<ReplaySummary, ReplayError>
where
    R: Read,
    T: ReplayTransmitter,
    C: WorkflowClock,
    S: crate::operation::EventSink<ReplayFrameEvidence>,
{
    let mut frames_completed = 0_u64;
    let mut bytes_completed = 0_u64;
    for (index, prepared) in plan.frames.iter().enumerate() {
        let sequence = index as u64;
        operation
            .cancellation()
            .check()
            .map_err(|source| ReplayError::Operation { sequence, source })?;
        let frame = reader
            .next_frame()
            .map_err(|source| ReplayError::Capture { sequence, source })?
            .ok_or_else(|| ReplayError::InvalidEvidence {
                sequence,
                message: "capture ended before the prepared replay manifest".to_owned(),
            })?;
        let capture_interface = replay_capture_interface(reader, &frame, sequence)?;
        if replay_frame_identity(&frame, capture_interface) != prepared.identity
            || frame.interface != prepared.source_interface_id
            || capture_interface != prepared.capture_interface
        {
            return Err(ReplayError::InvalidEvidence {
                sequence,
                message: "capture frame identity changed after replay preflight".to_owned(),
            });
        }
        let mode = replay_link_mode(sequence, frame.link_type, prepared.mode)?;
        if mode != prepared.mode {
            return Err(ReplayError::InvalidEvidence {
                sequence,
                message: "capture link mode changed after replay preflight".to_owned(),
            });
        }
        let interface = transmitter
            .validate_interface(&prepared.interface, mode, &frame)
            .map_err(|source| ReplayError::Transmission { sequence, source })?;
        if interface != prepared.interface {
            return Err(ReplayError::InvalidEvidence {
                sequence,
                message: "transmission interface changed after replay preflight".to_owned(),
            });
        }
        match clock.sleep_cancelled(prepared.delay, operation.cancellation()) {
            Ok(()) => {}
            Err(super::clock::SleepError::Clock(source)) => {
                return Err(ReplayError::Clock {
                    sequence,
                    message: source.to_string(),
                });
            }
            Err(super::clock::SleepError::Cancelled(source)) => {
                return Err(ReplayError::Operation { sequence, source });
            }
        }
        let transmission = transmitter
            .transmit(&interface, mode, &frame)
            .map_err(|source| ReplayError::Transmission { sequence, source })?;
        if transmission.interface != interface {
            return Err(ReplayError::InvalidEvidence {
                sequence,
                message: format!(
                    "backend reported transmission on {} (index {}) after validating {} (index {})",
                    transmission.interface.name,
                    transmission.interface.index,
                    interface.name,
                    interface.index
                ),
            });
        }
        validate_transmission_evidence(sequence, &frame, &transmission.report)?;
        frames_completed += 1;
        bytes_completed = bytes_completed
            .checked_add(u64::from(frame.captured_length))
            .expect("prepared replay bytes were already checked");
        sink.emit(ReplayFrameEvidence {
            source_sequence: sequence,
            source_interface_id: frame.interface,
            capture_interface,
            interface: transmission.interface,
            link_mode: mode,
            scheduled_delay: prepared.delay,
            bytes_sent: transmission.report.bytes_sent as u64,
            frame,
        })
        .map_err(|source| ReplayError::Event { sequence, source })?;
    }
    let sequence = plan.frames.len() as u64;
    if reader
        .next_frame()
        .map_err(|source| ReplayError::Capture { sequence, source })?
        .is_some()
    {
        return Err(ReplayError::InvalidEvidence {
            sequence,
            message: "capture gained frames after replay preflight".to_owned(),
        });
    }
    Ok(ReplaySummary {
        source_format: plan.source_format,
        timing: plan.timing,
        frames_attempted: frames_completed,
        frames_completed,
        bytes_completed,
        scheduled_duration: plan.scheduled_duration,
    })
}

fn replay_capture_interface<R: Read>(
    reader: &Reader<R>,
    frame: &Frame,
    sequence: u64,
) -> Result<Interface, ReplayError> {
    frame
        .interface
        .and_then(|interface| reader.interfaces().get(interface as usize))
        .or_else(|| {
            (reader.format() == Format::Pcap)
                .then(|| reader.interfaces().first())
                .flatten()
        })
        .copied()
        .ok_or_else(|| ReplayError::InvalidEvidence {
            sequence,
            message: "capture frame has no matching interface metadata".to_owned(),
        })
}

fn replay_frame_identity(frame: &Frame, interface: Interface) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"packetcraftr/replay-frame/v1\0");
    digest.update(frame.link_type.0.to_le_bytes());
    digest.update(frame.captured_length.to_le_bytes());
    digest.update(frame.original_length.to_le_bytes());
    digest.update(frame.interface.unwrap_or(u32::MAX).to_le_bytes());
    digest.update(interface.link_type.0.to_le_bytes());
    digest.update(interface.snap_len.to_le_bytes());
    match frame.timestamp.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            digest.update([0]);
            digest.update(duration.as_secs().to_le_bytes());
            digest.update(duration.subsec_nanos().to_le_bytes());
        }
        Err(error) => {
            let duration = error.duration();
            digest.update([1]);
            digest.update(duration.as_secs().to_le_bytes());
            digest.update(duration.subsec_nanos().to_le_bytes());
        }
    }
    digest.update(&frame.bytes);
    digest.finalize().into()
}

/// Streams, authorizes, schedules, and transmits a non-seekable capture. Use
/// this explicitly only when partial execution risk is acceptable.
pub fn replay_streaming<R, A, T, C, F>(
    reader: &mut Reader<R>,
    options: &ReplayOptions,
    authorizer: &mut A,
    transmitter: &mut T,
    clock: &mut C,
    emit: F,
) -> Result<ReplaySummary, ReplayError>
where
    R: Read,
    A: ReplayAuthorizer,
    T: ReplayTransmitter,
    C: WorkflowClock,
    F: FnMut(ReplayFrameEvidence) -> Result<(), ReplayError>,
{
    replay_capture(reader, options, authorizer, transmitter, clock, emit)
}

/// Compatibility implementation behind [`replay_streaming`].
fn replay_capture<R, A, T, C, F>(
    reader: &mut Reader<R>,
    options: &ReplayOptions,
    authorizer: &mut A,
    transmitter: &mut T,
    clock: &mut C,
    mut emit: F,
) -> Result<ReplaySummary, ReplayError>
where
    R: Read,
    A: ReplayAuthorizer,
    T: ReplayTransmitter,
    C: WorkflowClock,
    F: FnMut(ReplayFrameEvidence) -> Result<(), ReplayError>,
{
    let limits = options.limits.validate()?;
    let timing = options.timing.validate()?;
    let source_format = reader.format();
    let mut previous_timestamp = None;
    let mut frames_attempted = 0_u64;
    let mut frames_completed = 0_u64;
    let mut bytes_completed = 0_u64;
    let mut scheduled_duration = Duration::ZERO;

    loop {
        let sequence = frames_attempted;
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| ReplayError::Capture { sequence, source })?
        else {
            break;
        };
        let capture_interface = frame
            .interface
            .and_then(|interface| reader.interfaces().get(interface as usize))
            .or_else(|| {
                (reader.format() == Format::Pcap)
                    .then(|| reader.interfaces().first())
                    .flatten()
            })
            .copied()
            .ok_or_else(|| ReplayError::InvalidEvidence {
                sequence,
                message: "capture frame has no matching interface metadata".to_owned(),
            })?;

        let next_frames = frames_attempted
            .checked_add(1)
            .ok_or(ReplayError::FrameLimit {
                sequence,
                actual: u64::MAX,
                limit: limits.max_frames,
            })?;
        if next_frames > limits.max_frames {
            return Err(ReplayError::FrameLimit {
                sequence,
                actual: next_frames,
                limit: limits.max_frames,
            });
        }
        if frame.bytes.len() > limits.max_frame_bytes {
            return Err(ReplayError::FrameSizeLimit {
                sequence,
                actual: frame.bytes.len(),
                limit: limits.max_frame_bytes,
            });
        }
        let next_bytes = bytes_completed
            .checked_add(u64::from(frame.captured_length))
            .ok_or(ReplayError::ByteLimit {
                sequence,
                actual: u64::MAX,
                limit: limits.max_bytes,
            })?;
        if next_bytes > limits.max_bytes {
            return Err(ReplayError::ByteLimit {
                sequence,
                actual: next_bytes,
                limit: limits.max_bytes,
            });
        }
        frames_attempted = next_frames;

        let mode = replay_link_mode(sequence, frame.link_type, options.link_mode)?;
        let delay = match previous_timestamp {
            Some(previous) => match timing.delay_between(previous, frame.timestamp) {
                Ok(delay) => delay,
                Err(ReplayError::InvalidTiming { mode, value }) => {
                    return Err(ReplayError::Timing {
                        sequence,
                        mode,
                        value,
                    });
                }
                Err(error) => return Err(error),
            },
            None => Duration::ZERO,
        };
        let next_duration =
            scheduled_duration
                .checked_add(delay)
                .ok_or(ReplayError::DurationLimit {
                    sequence,
                    actual: Duration::MAX,
                    limit: limits.max_duration,
                })?;
        if next_duration > limits.max_duration {
            return Err(ReplayError::DurationLimit {
                sequence,
                actual: next_duration,
                limit: limits.max_duration,
            });
        }
        authorizer
            .authorize(&frame, mode)
            .map_err(|source| ReplayError::Authorization { sequence, source })?;
        let concrete_interface = transmitter
            .validate_interface(&options.interface, mode, &frame)
            .map_err(|source| ReplayError::Transmission { sequence, source })?;
        clock.sleep(delay).map_err(|source| ReplayError::Clock {
            sequence,
            message: source.to_string(),
        })?;

        let transmission = transmitter
            .transmit(&concrete_interface, mode, &frame)
            .map_err(|source| ReplayError::Transmission { sequence, source })?;
        if transmission.interface != concrete_interface {
            return Err(ReplayError::InvalidEvidence {
                sequence,
                message: format!(
                    "backend reported transmission on {} (index {}) after validating {} (index {})",
                    transmission.interface.name,
                    transmission.interface.index,
                    concrete_interface.name,
                    concrete_interface.index
                ),
            });
        }
        validate_transmission_evidence(sequence, &frame, &transmission.report)?;

        frames_completed = frames_completed
            .checked_add(1)
            .expect("completed frames cannot exceed validated attempted frames");
        bytes_completed = next_bytes;
        scheduled_duration = next_duration;
        previous_timestamp = Some(frame.timestamp);
        emit(ReplayFrameEvidence {
            source_sequence: sequence,
            source_interface_id: frame.interface,
            capture_interface,
            interface: transmission.interface,
            link_mode: mode,
            scheduled_delay: delay,
            bytes_sent: transmission.report.bytes_sent as u64,
            frame,
        })?;
    }

    Ok(ReplaySummary {
        source_format,
        timing,
        frames_attempted,
        frames_completed,
        bytes_completed,
        scheduled_duration,
    })
}
