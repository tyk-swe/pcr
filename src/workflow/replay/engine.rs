/// Streams, authorizes, schedules, and transmits a capture without retaining
/// more than the current frame.
pub fn replay_capture<R, A, T, C, F>(
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
