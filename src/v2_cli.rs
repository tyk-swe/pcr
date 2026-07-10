// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::SystemTime;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::json;

use crate::core::{
    parse_packet_expression, BuildContext, BuildMode, BuildOptions, Builder, DecodeOptions,
    Dissector, DocumentFormat, ExpressionOptions, Packet, PacketDocument,
    DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_LAYERS,
};
use crate::io::{CaptureReader, CapturedFrame, LinkType};

pub(crate) const OUTPUT_SCHEMA_V1: &str = "packetcraftr.output/v1";

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    #[default]
    Text,
    Json,
    Hex,
    Raw,
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
    Exchange(UnavailableArgs),
    /// Stream live captured frames.
    Capture(UnavailableArgs),
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

pub(crate) fn run_entrypoint() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            if code != 0 && env_requests_json() {
                let message = error.to_string();
                let envelope = error_envelope(command_from_env(), code, &message);
                return match emit_json(&envelope) {
                    Ok(()) => exit_code(code),
                    Err(write_error) => {
                        let _ = emit_stderr_error(&write_error.message);
                        exit_code(write_error.code)
                    }
                };
            }
            return if error.print().is_ok() {
                exit_code(code)
            } else {
                exit_code(5)
            };
        }
    };
    let output = cli.output;
    let command = cli.command.name();
    let streaming = matches!(&cli.command, Command::Read(_) | Command::Capture(_));
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if output == OutputFormat::Json {
                let envelope = error_envelope(Some(command), error.code, &error.message);
                let emitted = if streaming {
                    emit_json_compact(&envelope)
                } else {
                    emit_json(&envelope)
                };
                if let Err(write_error) = emitted {
                    let _ = emit_stderr_error(&write_error.message);
                    return exit_code(write_error.code);
                }
            } else if let Err(write_error) = emit_stderr_error(&error.message) {
                return exit_code(write_error.code);
            }
            exit_code(error.code)
        }
    }
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Build(_) => "build",
            Self::Dissect(_) => "dissect",
            Self::Read(_) => "read",
            Self::Interfaces => "interfaces",
            Self::Plan(_) => "plan",
            Self::Send(_) => "send",
            Self::Exchange(_) => "exchange",
            Self::Capture(_) => "capture",
            Self::Replay(_) => "replay",
            Self::Scan(_) => "scan",
            Self::Traceroute(_) => "traceroute",
            Self::Dns(_) => "dns",
            Self::Fuzz(_) => "fuzz",
            Self::Routes => "routes",
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Build(arguments) => run_build(arguments, cli.output),
        Command::Dissect(arguments) => run_dissect(arguments, cli.output),
        Command::Read(arguments) => run_read(arguments, cli.output),
        Command::Interfaces => run_interfaces(cli.output),
        Command::Plan(arguments)
        | Command::Send(arguments)
        | Command::Exchange(arguments)
        | Command::Capture(arguments)
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
    match output {
        OutputFormat::Text => {
            write_stdout_line(format_args!("built {} bytes", built.bytes.len()))?;
            write_stdout_line(format_args!("{}", spaced_hex(&built.bytes)))?;
            for diagnostic in &built.diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        OutputFormat::Hex => write_stdout_line(format_args!("{}", compact_hex(&built.bytes))),
        OutputFormat::Raw => write_raw(&built.bytes),
        OutputFormat::Json => emit_json(&json!({
            "schema": OUTPUT_SCHEMA_V1,
            "command": "build",
            "status": "success",
            "diagnostics": built.diagnostics,
            "result": {
                "bytes_hex": compact_hex(&built.bytes),
                "length": built.bytes.len(),
                "packet": PacketDocument::from_packet(&built.packet),
                "layout": built.layout,
                "requires_live_opt_in": built.requires_live_opt_in,
            }
        })),
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
    match output {
        OutputFormat::Text => {
            write_stdout_line(format_args!(
                "decoded {} bytes into {} layer(s)",
                decoded.original.len(),
                decoded.packet.len()
            ))?;
            for (index, layer) in decoded.packet.iter().enumerate() {
                write_stdout_line(format_args!("{index}: {}", layer.protocol_id()))?;
            }
            for diagnostic in &decoded.diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        OutputFormat::Hex => write_stdout_line(format_args!("{}", compact_hex(&decoded.original))),
        OutputFormat::Raw => write_raw(&decoded.original),
        OutputFormat::Json => emit_json(&json!({
            "schema": OUTPUT_SCHEMA_V1,
            "command": "dissect",
            "status": "success",
            "diagnostics": decoded.diagnostics,
            "result": {
                "bytes_hex": compact_hex(&decoded.original),
                "length": decoded.original.len(),
                "link_type": decoded.frame.link_type.0,
                "packet": PacketDocument::from_packet(&decoded.packet),
                "layout": decoded.layout,
            }
        })),
    }
}

fn run_read(arguments: ReadArgs, output: OutputFormat) -> Result<(), CliError> {
    if output == OutputFormat::Raw {
        return Err(CliError::new(
            2,
            "raw output is ambiguous for a multi-frame capture; use hex, JSON, or a capture writer",
        ));
    }
    let file = File::open(&arguments.path).map_err(|source| {
        CliError::new(
            5,
            format!("open {} failed: {source}", arguments.path.display()),
        )
    })?;
    let mut reader =
        CaptureReader::new(file).map_err(|source| CliError::new(3, source.to_string()))?;
    let mut index = 0usize;
    while let Some(frame) = reader
        .next_frame()
        .map_err(|source| CliError::new(3, source.to_string()))?
    {
        match output {
            OutputFormat::Text => write_stdout_line(format_args!(
                "{index}: dlt={} caplen={} wirelen={} {}",
                frame.link_type.0,
                frame.captured_length,
                frame.original_length,
                spaced_hex(&frame.bytes)
            ))?,
            OutputFormat::Hex => write_stdout_line(format_args!("{}", compact_hex(&frame.bytes)))?,
            OutputFormat::Json => emit_json_compact(&json!({
                "schema": OUTPUT_SCHEMA_V1,
                "command": "read",
                "status": "success",
                "diagnostics": [],
                "sequence": index,
                "result": {
                    "timestamp": frame.timestamp,
                    "captured_length": frame.captured_length,
                    "original_length": frame.original_length,
                    "link_type": frame.link_type.0,
                    "interface": frame.interface,
                    "direction": frame.direction,
                    "bytes_hex": compact_hex(&frame.bytes),
                }
            }))?,
            OutputFormat::Raw => unreachable!(),
        }
        index += 1;
    }
    Ok(())
}

#[cfg(all(feature = "live", not(windows)))]
fn run_interfaces(output: OutputFormat) -> Result<(), CliError> {
    if matches!(output, OutputFormat::Raw | OutputFormat::Hex) {
        return Err(CliError::new(2, "interfaces supports text or JSON output"));
    }
    let interfaces = pnet::datalink::interfaces();
    if output == OutputFormat::Json {
        let values = interfaces
            .iter()
            .map(|interface| {
                json!({
                    "name": interface.name,
                    "index": interface.index,
                    "mac": interface.mac.map(|value| value.to_string()),
                    "addresses": interface.ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "flags": interface.flags,
                })
            })
            .collect::<Vec<_>>();
        return emit_json(&json!({
            "schema": OUTPUT_SCHEMA_V1,
            "command": "interfaces",
            "status": "success",
            "diagnostics": [],
            "result": values,
        }));
    }
    for interface in interfaces {
        let addresses = interface
            .ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        write_stdout_line(format_args!(
            "{} (index {}): {}",
            interface.name, interface.index, addresses
        ))?;
    }
    Ok(())
}

#[cfg(all(feature = "live", windows))]
fn run_interfaces(_output: OutputFormat) -> Result<(), CliError> {
    Err(CliError::new(
        4,
        "Windows interface enumeration is unavailable in the portable profile; use a PacketcraftR build with the Windows native adapter when available (Npcap is required only for native Layer 2 capture and injection)",
    ))
}

#[cfg(not(feature = "live"))]
fn run_interfaces(_output: OutputFormat) -> Result<(), CliError> {
    Err(CliError::new(
        4,
        "interface enumeration requires the live feature",
    ))
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

fn compact_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
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
    write_stdout_line(format_args!("{rendered}"))
}

fn emit_json_compact(value: &impl Serialize) -> Result<(), CliError> {
    let rendered = serde_json::to_string(value)
        .map_err(|source| CliError::new(70, format!("serialize output failed: {source}")))?;
    write_stdout_line(format_args!("{rendered}"))
}

fn write_stdout_line(arguments: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_fmt(arguments)
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

fn emit_stderr_error(message: &str) -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "error: {message}")
        .and_then(|()| stderr.flush())
        .map_err(|source| CliError::new(5, format!("write stderr failed: {source}")))
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
}

impl CliError {
    fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn error_envelope(command: Option<&str>, code: u8, message: &str) -> serde_json::Value {
    let kind = match code {
        2 => "cli",
        3 => "packet",
        4 => "capability",
        5 => "io",
        6 => "policy",
        _ => "internal",
    };
    json!({
        "schema": OUTPUT_SCHEMA_V1,
        "command": command,
        "status": "error",
        "diagnostics": [],
        "error": {
            "code": format!("{kind}.{code}"),
            "kind": kind,
            "message": message,
            "causes": [],
        }
    })
}

fn env_requests_json() -> bool {
    let arguments = std::env::args().collect::<Vec<_>>();
    arguments
        .windows(2)
        .any(|pair| pair == ["--output", "json"])
        || arguments.iter().any(|argument| argument == "--output=json")
}

fn command_from_env() -> Option<&'static str> {
    const COMMANDS: &[&str] = &[
        "build",
        "dissect",
        "plan",
        "send",
        "exchange",
        "capture",
        "read",
        "replay",
        "scan",
        "traceroute",
        "dns",
        "fuzz",
        "interfaces",
        "routes",
    ];
    std::env::args().find_map(|argument| {
        COMMANDS
            .iter()
            .copied()
            .find(|command| *command == argument)
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
        assert_eq!(compact_hex(&bytes).len(), 512);
    }
}
