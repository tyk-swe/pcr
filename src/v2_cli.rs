// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::SystemTime;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

use crate::core::{
    parse_packet_expression, BuildContext, BuildMode, BuildOptions, Builder, DecodeOptions,
    Dissector, DocumentFormat, ExpressionOptions, Packet, PacketDocument,
    DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_LAYERS,
};
use crate::error::{ClassifiedError, ErrorClassification, FailureKind};
use crate::io::{CaptureReader, CapturedFrame, LinkType};
use crate::output::{
    AggregateErrorOutput, AggregateOutput, BuildCommandResult, CommandName, DissectCommandResult,
    InterfacesCommandResult, OutputContractError, OutputError, OutputFormat,
    ReadFrameCommandResult, StreamErrorRecord, StreamRecord,
};

#[derive(Debug, Parser)]
#[command(
    name = "packetcraftr",
    version,
    about = "Reflective packet construction, dissection, capture, and network tools",
    long_about = "PacketcraftR v0.2 alpha: arbitrary packet stacks, strict/permissive exact building, bounded dissection, and streaming offline capture. Live workflows remain capability-gated during the alpha series."
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build exact packet bytes from an expression or document.
    Build(BuildArgs),
    /// Decode a frame with bounded, registry-driven dissection.
    Dissect(DissectArgs),
    /// Stream frames from a classic PCAP or PCAPNG file.
    Read(ReadArgs),
    /// Enumerate local interfaces.
    Interfaces,
    /// Passively select route, source, MTU, and link mode.
    Plan(UnavailableArgs),
    /// Transmit a packet under traffic policy.
    Send(UnavailableArgs),
    /// Capture-ready request/response exchange.
    Exchange(UnavailableCaptureArgs),
    /// Stream live captured frames.
    Capture(UnavailableCaptureArgs),
    /// Replay a PCAP/PCAPNG stream.
    Replay(UnavailableArgs),
    /// Run a structured network scan.
    Scan(UnavailableArgs),
    /// Run structured traceroute probes.
    Traceroute(UnavailableArgs),
    /// Run a structured DNS operation.
    Dns(UnavailableArgs),
    /// Run bounded field-aware packet fuzzing.
    Fuzz(UnavailableArgs),
    /// Enumerate local routes.
    Routes,
}

#[derive(Debug, Args)]
struct RecipeArgs {
    /// One-off layer expression.
    #[arg(long, conflicts_with = "packet_file")]
    packet: Option<String>,
    /// Versioned JSON/YAML packet document.
    #[arg(long, value_name = "PATH", conflicts_with = "packet")]
    packet_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct BuildArgs {
    #[command(flatten)]
    recipe: RecipeArgs,
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    mode: CliBuildMode,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliBuildMode {
    #[default]
    Strict,
    Permissive,
}

#[derive(Debug, Args)]
struct DissectArgs {
    /// Whole-frame hexadecimal bytes.
    #[arg(long, conflicts_with = "file")]
    hex: Option<String>,
    /// File containing raw frame bytes.
    #[arg(long, value_name = "PATH", conflicts_with = "hex")]
    file: Option<PathBuf>,
    /// Open numeric DLT/link type (defaults to Ethernet/DLT 1).
    #[arg(long, default_value_t = 1)]
    link_type: u32,
}

#[derive(Debug, Args)]
struct ReadArgs {
    path: PathBuf,
}

#[derive(Debug, Args)]
struct UnavailableArgs {
    /// Packet expression (accepted for forward-compatible scripts).
    #[arg(long)]
    packet: Option<String>,
}

#[derive(Debug, Args)]
struct UnavailableCaptureArgs {
    /// Packet expression (accepted for forward-compatible scripts).
    #[arg(long)]
    packet: Option<String>,
    /// Aggregate backend capture-queue frame bound.
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_QUEUE_FRAMES)]
    max_queue_frames: usize,
    /// Aggregate retained/queued capture byte bound.
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_QUEUE_BYTES)]
    max_captured_bytes: usize,
    /// Maximum bytes retained from any one captured frame.
    #[arg(long, default_value_t = crate::io::DEFAULT_CAPTURE_SIZE_LIMIT)]
    snap_length: usize,
    /// Backend queue behavior when a configured bound is reached.
    #[arg(long, value_enum, default_value_t = CliCaptureOverflowPolicy::Fail)]
    overflow_policy: CliCaptureOverflowPolicy,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliCaptureOverflowPolicy {
    #[default]
    Fail,
    DropNewest,
    DropOldest,
}

pub(crate) fn run_entrypoint() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            if code != 0 {
                if let Some(output) = machine_format_from_env() {
                    let message = error.to_string();
                    let error = CliError::new(code, message);
                    let emitted = match output {
                        OutputFormat::Json => emit_json(&AggregateErrorOutput::error(
                            command_from_env(),
                            error.output_error(),
                        )),
                        OutputFormat::Ndjson => emit_json_compact(&StreamErrorRecord::error(
                            command_from_env(),
                            0,
                            error.output_error(),
                        )),
                        _ => unreachable!("machine_format_from_env returns structured formats"),
                    };
                    return match emitted {
                        Ok(()) => exit_code(code),
                        Err(write_error) => {
                            let _ = emit_stderr_error(&write_error.message);
                            exit_code(write_error.code)
                        }
                    };
                }
            }
            return if code == 0 {
                if error.print().is_ok() {
                    ExitCode::SUCCESS
                } else {
                    exit_code(5)
                }
            } else {
                match emit_stderr_message(&error.to_string()) {
                    Ok(()) => exit_code(code),
                    Err(_) => exit_code(5),
                }
            };
        }
    };
    let output = cli.output;
    let command = cli.command.name();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let emitted = match output {
                OutputFormat::Json => emit_json(&AggregateErrorOutput::error(
                    Some(command),
                    error.output_error(),
                )),
                OutputFormat::Ndjson => emit_json_compact(&StreamErrorRecord::error(
                    Some(command),
                    error.sequence.unwrap_or(0),
                    error.output_error(),
                )),
                _ => emit_stderr_error(&error.message),
            };
            if let Err(write_error) = emitted {
                if matches!(output, OutputFormat::Json | OutputFormat::Ndjson) {
                    let _ = emit_stderr_error(&write_error.message);
                };
                return exit_code(write_error.code);
            }
            exit_code(error.code)
        }
    }
}

impl Command {
    fn name(&self) -> CommandName {
        match self {
            Self::Build(_) => CommandName::Build,
            Self::Dissect(_) => CommandName::Dissect,
            Self::Read(_) => CommandName::Read,
            Self::Interfaces => CommandName::Interfaces,
            Self::Plan(_) => CommandName::Plan,
            Self::Send(_) => CommandName::Send,
            Self::Exchange(_) => CommandName::Exchange,
            Self::Capture(_) => CommandName::Capture,
            Self::Replay(_) => CommandName::Replay,
            Self::Scan(_) => CommandName::Scan,
            Self::Traceroute(_) => CommandName::Traceroute,
            Self::Dns(_) => CommandName::Dns,
            Self::Fuzz(_) => CommandName::Fuzz,
            Self::Routes => CommandName::Routes,
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    cli.command
        .name()
        .require_format(cli.output)
        .map_err(CliError::classified)?;
    match cli.command {
        Command::Build(arguments) => run_build(arguments, cli.output),
        Command::Dissect(arguments) => run_dissect(arguments, cli.output),
        Command::Read(arguments) => run_read(arguments, cli.output),
        Command::Interfaces => run_interfaces(cli.output),
        Command::Plan(arguments)
        | Command::Send(arguments)
        | Command::Replay(arguments)
        | Command::Scan(arguments)
        | Command::Traceroute(arguments)
        | Command::Dns(arguments)
        | Command::Fuzz(arguments) => {
            let _ = arguments.packet;
            Err(CliError::new(
                4,
                "this live/tool workflow is capability-gated in 0.2.0-alpha.1",
            ))
        }
        Command::Exchange(arguments) | Command::Capture(arguments) => {
            let _ = (
                arguments.packet,
                arguments.max_queue_frames,
                arguments.max_captured_bytes,
                arguments.snap_length,
                arguments.overflow_policy,
            );
            Err(CliError::new(
                4,
                "this live/tool workflow is capability-gated in 0.2.0-alpha.1",
            ))
        }
        Command::Routes => Err(CliError::new(
            4,
            "native route enumeration is capability-gated in 0.2.0-alpha.1",
        )),
    }
}

fn run_build(arguments: BuildArgs, output: OutputFormat) -> Result<(), CliError> {
    let registry = Arc::new(crate::protocols::default_registry().map_err(|source| {
        CliError::new(70, format!("built-in registry invariant failed: {source}"))
    })?);
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
        (Some(value), None) => crate::core::decode_hex(&value)
            .map_err(|source| CliError::new(2, source.to_string()))?
            .to_vec(),
        (None, Some(path)) => read_bounded_file(&path, DEFAULT_MAX_DOCUMENT_BYTES)?,
        (None, None) => read_stdin_bounded(DEFAULT_MAX_DOCUMENT_BYTES)?,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };
    let registry = Arc::new(crate::protocols::default_registry().map_err(|source| {
        CliError::new(70, format!("built-in registry invariant failed: {source}"))
    })?);
    let decoded = Dissector::new(registry)
        .decode(
            CapturedFrame::new(SystemTime::now(), LinkType(arguments.link_type), bytes)
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
    let file = File::open(&arguments.path).map_err(|source| {
        CliError::new(
            5,
            format!("open {} failed: {source}", arguments.path.display()),
        )
    })?;
    let mut reader =
        CaptureReader::new(file).map_err(|source| CliError::new(3, source.to_string()))?;
    let mut sequence = 0_u64;
    loop {
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| CliError::new(3, source.to_string()).at_sequence(sequence))?
        else {
            return Ok(());
        };
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
        sequence = sequence.checked_add(1).ok_or_else(|| {
            CliError::classified(OutputContractError::SequenceOverflow).at_sequence(sequence)
        })?;
    }
}

fn run_interfaces(output: OutputFormat) -> Result<(), CliError> {
    let interfaces = crate::io::InterfaceProvider::interfaces(&crate::io::SystemInterfaceProvider)
        .map_err(CliError::classified)?;
    let result = InterfacesCommandResult::new(interfaces);
    match output {
        OutputFormat::Text => {
            for interface in result.interfaces {
                write_stdout_line(format_args!(
                    "{} (index {}): {}",
                    interface.name,
                    interface.index,
                    interface.addresses.join(", ")
                ))?;
            }
            Ok(())
        }
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Interfaces,
            result,
            Vec::new(),
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Interfaces,
                format: output,
            },
        )),
    }
}

fn read_recipe(
    arguments: RecipeArgs,
    registry: &crate::core::ProtocolRegistry,
) -> Result<Packet, CliError> {
    let stdin = read_nonterminal_stdin_bounded(DEFAULT_MAX_DOCUMENT_BYTES)?;
    let RecipeArgs {
        packet,
        packet_file,
    } = arguments;
    let source_count = usize::from(packet.is_some())
        + usize::from(packet_file.is_some())
        + usize::from(stdin.is_some());
    if source_count != 1 {
        return Err(CliError::new(
            2,
            "exactly one of --packet, --packet-file, or non-empty stdin is required",
        ));
    }

    let (input, path) = match (packet, packet_file, stdin) {
        (Some(expression), None, None) => return parse_expression(&expression, registry),
        (None, Some(path), None) => {
            let bytes = read_bounded_file(&path, DEFAULT_MAX_DOCUMENT_BYTES)?;
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(2, format!("packet document is not UTF-8: {source}"))
            })?;
            (input, Some(path))
        }
        (None, None, Some(bytes)) => {
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(2, format!("stdin recipe is not UTF-8: {source}"))
            })?;
            (input, None)
        }
        _ => unreachable!("source count was validated"),
    };
    let trimmed = input.trim_start();
    let format = path
        .as_deref()
        .and_then(document_format_from_path)
        .or_else(|| trimmed.starts_with('{').then_some(DocumentFormat::Json))
        .or_else(|| {
            (trimmed.starts_with("schema:") || trimmed.starts_with("---"))
                .then_some(DocumentFormat::Yaml)
        });
    if let Some(format) = format {
        return PacketDocument::parse(&input, format, DEFAULT_MAX_DOCUMENT_BYTES)
            .and_then(|document| document.to_packet(registry, DEFAULT_MAX_LAYERS))
            .map_err(|source| CliError::new(2, source.to_string()));
    }
    parse_expression(&input, registry)
}

fn parse_expression(
    input: &str,
    registry: &crate::core::ProtocolRegistry,
) -> Result<Packet, CliError> {
    parse_packet_expression(input, registry, ExpressionOptions::default())
        .map_err(|source| CliError::new(2, source.to_string()))
}

fn document_format_from_path(path: &Path) -> Option<DocumentFormat> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "json" => Some(DocumentFormat::Json),
        "yaml" | "yml" => Some(DocumentFormat::Yaml),
        _ => None,
    }
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, CliError> {
    let file = File::open(path)
        .map_err(|source| CliError::new(2, format!("open {} failed: {source}", path.display())))?;
    read_bounded(file, maximum)
}

fn read_stdin_bounded(maximum: usize) -> Result<Vec<u8>, CliError> {
    read_bounded(io::stdin().lock(), maximum)
}

fn read_nonterminal_stdin_bounded(maximum: usize) -> Result<Option<Vec<u8>>, CliError> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Ok(None);
    }
    let bytes = read_bounded_allow_empty(stdin.lock(), maximum)?;
    Ok((!bytes.is_empty()).then_some(bytes))
}

fn read_bounded(reader: impl Read, maximum: usize) -> Result<Vec<u8>, CliError> {
    let bytes = read_bounded_allow_empty(reader, maximum)?;
    if bytes.is_empty() {
        return Err(CliError::new(
            2,
            "one of --packet, --packet-file, or non-empty stdin is required",
        ));
    }
    Ok(bytes)
}

fn read_bounded_allow_empty(reader: impl Read, maximum: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    reader
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::new(2, format!("read packet input failed: {source}")))?;
    if bytes.len() > maximum {
        return Err(CliError::new(
            2,
            format!("packet input exceeds {maximum} byte limit"),
        ));
    }
    Ok(bytes)
}

fn spaced_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        use std::fmt::Write as _;
        if index != 0 {
            output.push(' ');
        }
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn emit_json(value: &impl Serialize) -> Result<(), CliError> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|source| CliError::new(70, format!("serialize output failed: {source}")))?;
    write_machine_line(&rendered)
}

fn emit_json_compact(value: &impl Serialize) -> Result<(), CliError> {
    let rendered = serde_json::to_string(value)
        .map_err(|source| CliError::new(70, format!("serialize output failed: {source}")))?;
    write_machine_line(&rendered)
}

fn write_stdout_line(arguments: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    let rendered = terminal_safe(&arguments.to_string());
    write_machine_line(&rendered)
}

fn write_machine_line(rendered: &str) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

fn emit_stderr_error(message: &str) -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "error: {}", terminal_safe(message))
        .and_then(|()| stderr.flush())
        .map_err(|source| CliError::new(5, format!("write stderr failed: {source}")))
}

fn emit_stderr_message(message: &str) -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "{}", terminal_safe(message))
        .and_then(|()| stderr.flush())
        .map_err(|source| CliError::new(5, format!("write stderr failed: {source}")))
}

fn terminal_safe(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => safe.push_str("\\n"),
            '\r' => safe.push_str("\\r"),
            '\t' => safe.push_str("\\t"),
            character
                if character.is_control()
                    || matches!(
                        character,
                        '\u{061c}'
                            | '\u{200b}'..='\u{200f}'
                            | '\u{202a}'..='\u{202e}'
                            | '\u{2060}'..='\u{206f}'
                            | '\u{feff}'
                    ) =>
            {
                use std::fmt::Write as _;
                let _ = write!(safe, "\\u{{{:x}}}", character as u32);
            }
            character => safe.push(character),
        }
    }
    safe
}

fn write_raw(bytes: &[u8]) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

#[derive(Debug)]
struct CliError {
    code: u8,
    message: String,
    classification: ErrorClassification,
    causes: Vec<String>,
    sequence: Option<u64>,
}

impl CliError {
    fn new(code: u8, message: impl Into<String>) -> Self {
        let kind = match code {
            2 => FailureKind::Cli,
            3 => FailureKind::Packet,
            4 => FailureKind::Capability,
            5 => FailureKind::Io,
            6 => FailureKind::Policy,
            _ => FailureKind::Internal,
        };
        Self {
            code,
            message: message.into(),
            classification: ErrorClassification::new(
                match kind {
                    FailureKind::Cli => "cli.error",
                    FailureKind::Packet => "packet.error",
                    FailureKind::Capability => "capability.unavailable",
                    FailureKind::Io => "io.runtime",
                    FailureKind::Policy => "policy.denied",
                    FailureKind::Internal => "internal.error",
                },
                kind,
                None,
            ),
            causes: Vec::new(),
            sequence: None,
        }
    }

    fn classified(error: impl ClassifiedError + std::fmt::Display) -> Self {
        let classification = error.classification();
        let causes = error.causes();
        Self {
            code: classification.exit_code(),
            message: error.to_string(),
            classification,
            causes,
            sequence: None,
        }
    }

    fn at_sequence(mut self, sequence: u64) -> Self {
        self.sequence = Some(sequence);
        self
    }

    fn output_error(&self) -> OutputError {
        OutputError::new(
            self.classification,
            self.message.clone(),
            self.causes.clone(),
        )
    }
}

fn machine_format_from_env() -> Option<OutputFormat> {
    let arguments = std::env::args().collect::<Vec<_>>();
    arguments.iter().enumerate().find_map(|(index, argument)| {
        let value = if argument == "--output" {
            arguments.get(index + 1).map(String::as_str)
        } else {
            argument.strip_prefix("--output=")
        }?;
        match value {
            "json" => Some(OutputFormat::Json),
            "ndjson" => Some(OutputFormat::Ndjson),
            _ => None,
        }
    })
}

fn command_from_env() -> Option<CommandName> {
    const COMMANDS: &[(&str, CommandName)] = &[
        ("build", CommandName::Build),
        ("dissect", CommandName::Dissect),
        ("plan", CommandName::Plan),
        ("send", CommandName::Send),
        ("exchange", CommandName::Exchange),
        ("capture", CommandName::Capture),
        ("read", CommandName::Read),
        ("replay", CommandName::Replay),
        ("scan", CommandName::Scan),
        ("traceroute", CommandName::Traceroute),
        ("dns", CommandName::Dns),
        ("fuzz", CommandName::Fuzz),
        ("interfaces", CommandName::Interfaces),
        ("routes", CommandName::Routes),
    ];
    std::env::args().find_map(|argument| {
        COMMANDS
            .iter()
            .find_map(|(name, command)| (*name == argument).then_some(*command))
    })
}

fn exit_code(code: u8) -> ExitCode {
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_sources_are_mutually_exclusive() {
        let result = Cli::try_parse_from([
            "packetcraftr",
            "build",
            "--packet",
            "raw()",
            "--packet-file",
            "packet.json",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn whole_frame_hex_is_not_truncated() {
        let bytes = (0u8..=255).collect::<Vec<_>>();
        assert_eq!(
            crate::output::WireFrameOutput::new(bytes).bytes_hex.len(),
            512
        );
    }

    #[test]
    fn terminal_text_escapes_controls_and_directional_overrides() {
        let safe = terminal_safe("line\n\u{1b}[31m\u{202e}tail");
        assert_eq!(safe, "line\\n\\u{1b}[31m\\u{202e}tail");
        assert!(!safe.chars().any(char::is_control));
    }

    #[test]
    fn classified_live_errors_use_the_frozen_cli_exit_contract() {
        let capability = CliError::classified(crate::io::LiveIoError::Privilege {
            message: "permission denied".to_owned(),
        });
        assert_eq!(capability.code, 4);
        assert_eq!(capability.classification.code, "capability.privilege");

        let runtime = CliError::classified(crate::io::LiveIoError::PartialSend {
            expected: 10,
            actual: 9,
        });
        assert_eq!(runtime.code, 5);
        assert_eq!(runtime.classification.code, "io.partial_send");

        let dual = CliError::classified(crate::ClientError::OperationAndCaptureShutdown {
            operation: crate::io::LiveIoError::Send {
                message: "send failed".to_owned(),
            },
            shutdown: crate::io::LiveIoError::Capture {
                message: "join failed".to_owned(),
            },
        });
        assert_eq!(dual.causes.len(), 2);
        let envelope =
            AggregateErrorOutput::error(Some(CommandName::Exchange), dual.output_error());
        let envelope = serde_json::to_value(envelope).unwrap();
        assert_eq!(envelope["error"]["causes"].as_array().unwrap().len(), 2);
    }
}
