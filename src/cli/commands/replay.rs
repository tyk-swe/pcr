// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Capture replay command.

fn replay_timing(arguments: &ReplayArgs) -> Result<ReplayTiming, CliError> {
    let timing = if let Some(rate) = arguments.rate {
        if matches!(arguments.timing, CliReplayTiming::Immediate) {
            return Err(CliError::new(
                2,
                "--rate cannot be combined with --timing immediate",
            ));
        }
        ReplayTiming::FixedRate(rate)
    } else if let Some(speed) = arguments.speed {
        if matches!(arguments.timing, CliReplayTiming::Immediate) {
            return Err(CliError::new(
                2,
                "--speed cannot be combined with --timing immediate",
            ));
        }
        ReplayTiming::Scaled(1.0 / speed)
    } else {
        match arguments.timing {
            CliReplayTiming::Original => ReplayTiming::Original,
            CliReplayTiming::Immediate => ReplayTiming::Immediate,
        }
    };
    timing.validate().map_err(CliError::classified)
}

fn requested_replay_interface(selector: &str) -> Result<InterfaceId, CliError> {
    let index = validate_interface_selector("replay", Some(selector))?.unwrap_or(0);
    Ok(InterfaceId {
        name: selector.to_owned(),
        index,
    })
}

fn run_replay(arguments: ReplayArgs, output: OutputFormat) -> Result<(), CliError> {
    validate_capture_stream_limits(
        arguments.policy.max_packets,
        arguments.policy.max_bytes,
        arguments.max_frame_bytes,
        arguments.max_interfaces,
    )?;
    let timing = replay_timing(&arguments)?;
    let requested_interface = requested_replay_interface(&arguments.interface)?;
    let policy = arguments.policy.clone().into_policy();
    policy.validate().map_err(CliError::classified)?;
    let limits = ReplayLimits {
        max_frames: policy.max_packets_per_operation,
        max_bytes: policy.max_bytes_per_operation,
        max_frame_bytes: arguments.max_frame_bytes,
        max_duration: Duration::from_millis(arguments.max_duration_ms),
    }
    .validate()
    .map_err(CliError::classified)?;
    let file = File::open(&arguments.path).map_err(|source| {
        CliError::new(
            5,
            format!("open {} failed: {source}", arguments.path.display()),
        )
    })?;
    let mut reader = Reader::with_limits(file, arguments.max_frame_bytes, arguments.max_interfaces)
        .map_err(CliError::classified)?;
    let registry = default_registry_arc()?;
    let mut authorizer =
        ReplaySystemAuthorizer::new(policy, registry, arguments.allow_malformed_live);
    let options = ReplayOptions {
        interface: requested_interface.clone(),
        link_mode: arguments.link_mode.into(),
        timing,
        limits,
    };
    let mut transmitter = ReplaySystemTransmitter::new();
    let mut clock = SystemReplayClock;
    let started = Instant::now();

    match output {
        OutputFormat::Text => {
            let summary = replay_capture(
                &mut reader,
                &options,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| {
                    let sequence = evidence.source_sequence;
                    let result = ReplayFrameCommandResult::try_from_evidence(evidence)
                        .map_err(|source| ReplayError::output(sequence, source.to_string()))?;
                    write_stdout_line(format_args!(
                        "{}: sent {} bytes via {} (index {}, {:?}) dlt={} {}",
                        result.source_sequence,
                        result.bytes_sent,
                        result.interface.name,
                        result.interface.index,
                        result.link_mode,
                        result.frame.link_type,
                        spaced_hex(result.frame.bytes())
                    ))
                    .map_err(|source| ReplayError::output(result.source_sequence, source.message))
                },
            )
            .map_err(replay_cli_error)?;
            write_stdout_line(format_args!(
                "replayed {} frame(s), {} byte(s), scheduled delay {:?}",
                summary.frames_completed, summary.bytes_completed, summary.scheduled_duration
            ))
        }
        OutputFormat::Json => {
            let mut frames = Vec::new();
            let summary = replay_capture(
                &mut reader,
                &options,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| {
                    let sequence = evidence.source_sequence;
                    let result = ReplayFrameCommandResult::try_from_evidence(evidence)
                        .map_err(|source| ReplayError::output(sequence, source.to_string()))?;
                    frames.push(result);
                    Ok(())
                },
            )
            .map_err(replay_cli_error)?;
            let stats = replay_stats(&summary, started.elapsed());
            let result = ReplayCommandResult::from_summary(
                summary,
                requested_interface,
                options.link_mode,
                frames,
            );
            emit_json(
                &AggregateOutput::success(CommandName::Replay, result, Vec::new())
                    .with_stats(stats),
            )
        }
        OutputFormat::Ndjson => {
            let summary = replay_capture(
                &mut reader,
                &options,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| {
                    let sequence = evidence.source_sequence;
                    let result = ReplayFrameCommandResult::try_from_evidence(evidence)
                        .map_err(|source| ReplayError::output(sequence, source.to_string()))?;
                    emit_json_compact(&StreamRecord::success(
                        CommandName::Replay,
                        sequence,
                        result,
                        Vec::new(),
                    ))
                    .map_err(|source| ReplayError::output(sequence, source.message))
                },
            )
            .map_err(replay_cli_error)?;
            let sequence = summary.frames_completed;
            let stats = replay_stats(&summary, started.elapsed());
            let result = ReplayCommandResult::from_summary(
                summary,
                requested_interface,
                options.link_mode,
                Vec::new(),
            );
            emit_json_compact(
                &StreamRecord::success(CommandName::Replay, sequence, result, Vec::new())
                    .with_stats(stats),
            )
            .map_err(|error| error.at_sequence(sequence))
        }
        OutputFormat::Pcap | OutputFormat::Pcapng => {
            let format = capture_file_format(output)?;
            let stdout = io::stdout();
            let mut writer = replay_capture_writer(
                &reader,
                stdout.lock(),
                format,
                limits,
                arguments.max_interfaces,
            )?;
            let mut interfaces = Vec::<(Option<u32>, u32)>::new();
            replay_capture(
                &mut reader,
                &options,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| {
                    write_replay_capture_evidence(&mut writer, format, &mut interfaces, evidence)
                },
            )
            .map_err(replay_cli_error)?;
            writer.flush().map_err(CliError::classified)
        }
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Replay,
                format: output,
            },
        )),
    }
}

fn replay_capture_writer<W: Write>(
    reader: &Reader<File>,
    output: W,
    format: Format,
    limits: ReplayLimits,
    max_interfaces: usize,
) -> Result<Writer<W>, CliError> {
    let mut writer = match format {
        Format::Pcap => {
            if reader.format() != Format::Pcap {
                return Err(CliError::classified(
                    crate::capture::Error::MetadataNotRepresentable {
                        format,
                        field: "pcapng replay evidence",
                    },
                ));
            }
            let interface = reader.interfaces()[0];
            Writer::pcap_with_metadata(
                output,
                interface.link_type,
                reader.endianness(),
                interface.timestamp_resolution,
                interface.snap_len as usize,
                limits.max_frame_bytes,
            )
        }
        Format::PcapNg => Writer::pcapng_with_resource_limits(
            output,
            reader.endianness(),
            limits.max_frame_bytes,
            max_interfaces,
        ),
    }
    .map_err(CliError::classified)?;
    writer
        .set_stream_limits(Limits {
            max_frames: limits.max_frames,
            max_bytes: limits.max_bytes,
        })
        .map_err(CliError::classified)?;
    Ok(writer)
}

fn write_replay_capture_evidence<W: Write>(
    writer: &mut Writer<W>,
    format: Format,
    interfaces: &mut Vec<(Option<u32>, u32)>,
    evidence: crate::workflow_api::ReplayFrameEvidence,
) -> Result<(), ReplayError> {
    let sequence = evidence.source_sequence;
    let mut frame = evidence.frame;
    frame.interface = match format {
        Format::Pcap => None,
        Format::PcapNg => {
            let interface = match interfaces
                .iter()
                .find(|(source, _)| *source == evidence.source_interface_id)
            {
                Some((_, interface)) => *interface,
                None => {
                    let interface = writer
                        .add_interface_description(evidence.capture_interface)
                        .map_err(|source| ReplayError::output(sequence, source.to_string()))?;
                    interfaces.push((evidence.source_interface_id, interface));
                    interface
                }
            };
            Some(interface)
        }
    };
    writer
        .write_frame(&frame)
        .map_err(|source| ReplayError::output(sequence, source.to_string()))
}

fn replay_stats(
    summary: &crate::workflow_api::ReplaySummary,
    elapsed: Duration,
) -> crate::output::envelope::Stats {
    crate::output::envelope::Stats {
        packets_attempted: summary.frames_attempted,
        packets_completed: summary.frames_completed,
        bytes: summary.bytes_completed,
        elapsed,
        capture: crate::net::capture::Statistics::default().into(),
    }
}

fn replay_cli_error(error: ReplayError) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}
