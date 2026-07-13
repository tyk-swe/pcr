// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Offline build, dissect, and capture-read commands.

fn run_build(arguments: BuildArgs, output: OutputFormat) -> Result<(), CliError> {
    let registry = default_registry_arc()?;
    let packet = read_recipe(arguments.recipe, &registry)?;
    let built = Builder::new(registry)
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: match arguments.mode {
                    CliBuildMode::Strict => BuildMode::Strict,
                    CliBuildMode::Permissive => BuildMode::Permissive,
                },
                ..BuildOptions::default()
            },
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    let (result, diagnostics) = BuildCommandResult::from_built(built);
    match output {
        OutputFormat::Text => {
            write_stdout_line(format_args!("built {} bytes", result.length))?;
            write_stdout_line(format_args!("{}", spaced_hex(result.bytes())))?;
            for diagnostic in &diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        OutputFormat::Hex => write_stdout_line(format_args!("{}", result.bytes_hex)),
        OutputFormat::Raw => write_raw(result.bytes()),
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Build,
            result,
            diagnostics,
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Build,
                format: output,
            },
        )),
    }
}

fn run_dissect(arguments: DissectArgs, output: OutputFormat) -> Result<(), CliError> {
    let bytes = match (arguments.hex, arguments.file) {
        (Some(value), None) => crate::packet::internal::decode_hex(&value)
            .map_err(|source| CliError::new(2, source.to_string()))?
            .to_vec(),
        (None, Some(path)) => read_bounded_file(&path, DEFAULT_MAX_DOCUMENT_BYTES)?,
        (None, None) => read_stdin_bounded(DEFAULT_MAX_DOCUMENT_BYTES)?,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };
    let registry = default_registry_arc()?;
    let decoded = Dissector::new(registry)
        .decode(
            Frame::new(SystemTime::now(), LinkType(arguments.link_type), bytes)
                .map_err(|source| CliError::new(3, source.to_string()))?,
            DecodeOptions::default(),
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    let (result, diagnostics) = DissectCommandResult::from_decoded(decoded);
    match output {
        OutputFormat::Text => {
            write_stdout_line(format_args!(
                "decoded {} bytes into {} layer(s)",
                result.length,
                result.packet.layers.len()
            ))?;
            for (index, layer) in result.packet.layers.iter().enumerate() {
                write_stdout_line(format_args!("{index}: {}", layer.protocol))?;
            }
            for diagnostic in &diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        OutputFormat::Hex => write_stdout_line(format_args!("{}", result.bytes_hex)),
        OutputFormat::Raw => write_raw(result.bytes()),
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Dissect,
            result,
            diagnostics,
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Dissect,
                format: output,
            },
        )),
    }
}

fn run_read(arguments: ReadArgs, output: OutputFormat) -> Result<(), CliError> {
    let ReadArgs {
        path,
        max_frames,
        max_bytes,
        max_frame_bytes,
        max_interfaces,
    } = arguments;
    validate_capture_stream_limits(max_frames, max_bytes, max_frame_bytes, max_interfaces)?;
    let file = File::open(&path)
        .map_err(|source| CliError::new(5, format!("open {} failed: {source}", path.display())))?;
    let mut reader =
        Reader::with_limits(file, max_frame_bytes, max_interfaces).map_err(CliError::classified)?;
    let stream_limits = Limits {
        max_frames,
        max_bytes,
    };
    if matches!(output, OutputFormat::Pcap | OutputFormat::Pcapng) {
        let format = capture_file_format(output)?;
        let stdout = io::stdout();
        let (_output, _report) = transcode(&mut reader, stdout.lock(), format, stream_limits)
            .map_err(CliError::classified)?;
        return Ok(());
    }

    let mut sequence = 0_u64;
    let mut captured_bytes = 0_u64;
    loop {
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| CliError::classified(source).at_sequence(sequence))?
        else {
            return Ok(());
        };
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            CliError::classified(OutputContractError::SequenceOverflow).at_sequence(sequence)
        })?;
        if next_sequence > max_frames {
            return Err(
                CliError::classified(crate::capture::Error::FrameLimitExceeded {
                    actual: next_sequence,
                    limit: max_frames,
                })
                .at_sequence(sequence),
            );
        }
        let next_bytes = captured_bytes
            .checked_add(u64::from(frame.captured_length))
            .ok_or_else(|| {
                CliError::classified(crate::capture::Error::StreamByteLimitExceeded {
                    actual: u64::MAX,
                    limit: max_bytes,
                })
                .at_sequence(sequence)
            })?;
        if next_bytes > max_bytes {
            return Err(
                CliError::classified(crate::capture::Error::StreamByteLimitExceeded {
                    actual: next_bytes,
                    limit: max_bytes,
                })
                .at_sequence(sequence),
            );
        }
        let result = ReadFrameCommandResult::try_from_frame(frame)
            .map_err(|source| CliError::classified(source).at_sequence(sequence))?;
        match output {
            OutputFormat::Text => write_stdout_line(format_args!(
                "{sequence}: dlt={} caplen={} wirelen={} {}",
                result.frame.link_type,
                result.frame.captured_length,
                result.frame.original_length,
                spaced_hex(result.frame.bytes())
            ))?,
            OutputFormat::Hex => write_stdout_line(format_args!("{}", result.frame.bytes_hex))?,
            OutputFormat::Ndjson => emit_json_compact(&StreamRecord::success(
                CommandName::Read,
                sequence,
                result,
                Vec::new(),
            ))
            .map_err(|error| error.at_sequence(sequence))?,
            _ => {
                return Err(CliError::classified(
                    OutputContractError::UnsupportedFormat {
                        command: CommandName::Read,
                        format: output,
                    },
                ))
            }
        }
        sequence = next_sequence;
        captured_bytes = next_bytes;
    }
}

fn validate_capture_stream_limits(
    max_frames: u64,
    max_bytes: u64,
    max_frame_bytes: usize,
    max_interfaces: usize,
) -> Result<(), CliError> {
    if max_frames == 0 || max_bytes == 0 || max_frame_bytes == 0 || max_interfaces == 0 {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_limit",
                Kind::Cli,
                Some("use finite non-zero capture frame, byte, packet, and interface limits"),
            ),
            "capture stream limits must be non-zero",
            Vec::new(),
        ));
    }
    if u64::try_from(max_frame_bytes).unwrap_or(u64::MAX) > max_bytes {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_limit",
                Kind::Cli,
                Some("set max-frame-bytes no higher than the aggregate max-bytes budget"),
            ),
            format!("max-frame-bytes {max_frame_bytes} exceeds max-bytes {max_bytes}"),
            Vec::new(),
        ));
    }
    Ok(())
}
