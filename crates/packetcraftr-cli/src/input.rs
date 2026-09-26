// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod fingerprint;
pub(crate) use fingerprint::Fingerprint;

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};

use packetcraftr_core as core;
use packetcraftr_core::capture_file::Reader;
use packetcraftr_core::capture_file::ReaderOptions;
use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Kind;
use packetcraftr_core::packet::Packet;

use super::command_options::{CaptureReaderBoundsArgs, OfflineCaptureLimitsArgs, RecipeArgs};
use super::errors::CliError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputKind {
    Recipe,
    Frame,
    Capture,
}

impl InputKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Recipe => "packet",
            Self::Frame => "frame",
            Self::Capture => "capture",
        }
    }

    const fn options(self) -> &'static str {
        match self {
            Self::Recipe => "--packet, --packet-file, or redirect non-empty stdin",
            Self::Frame => "--hex, --file, or redirect non-empty stdin",
            Self::Capture => "a capture path, or use - with redirected capture stdin",
        }
    }

    const fn remediation(self) -> &'static str {
        match self {
            Self::Recipe => {
                "provide --packet, --packet-file, or pipe a non-empty packet recipe to stdin"
            }
            Self::Frame => "provide --hex, --file, or pipe non-empty frame bytes to stdin",
            Self::Capture => "provide a capture path or pipe PCAP/PCAPNG bytes with - as the path",
        }
    }

    fn oversized_error(self, actual: usize, limit: usize) -> CliError {
        match self {
            Self::Recipe | Self::Capture => CliError::new(
                Kind::Usage,
                format!("{} input exceeds {limit} byte limit", self.label()),
            ),
            Self::Frame => {
                CliError::classified(core::decode::Error::PacketSizeLimit { actual, limit })
            }
        }
    }
}

fn missing_input_error(kind: InputKind) -> CliError {
    CliError::from_classification(
        Classification::new("cli.input_source", Kind::Usage, Some(kind.remediation())),
        format!(
            "{} input is required: provide {}",
            kind.label(),
            kind.options()
        ),
        Vec::new(),
    )
}

fn require_redirected_stdin(kind: InputKind, stdin_is_terminal: bool) -> Result<(), CliError> {
    if stdin_is_terminal {
        Err(missing_input_error(kind))
    } else {
        Ok(())
    }
}

pub(crate) fn read_recipe(
    arguments: RecipeArgs,
    registry: &core::registry::Registry,
    max_layers: usize,
) -> Result<Packet, CliError> {
    let RecipeArgs {
        packet,
        packet_file,
        payload_file,
    } = arguments;

    let mut packet = resolve_recipe(packet, packet_file, registry, max_layers)?;
    if let Some(spec) = payload_file {
        apply_payload_file(&mut packet, &spec)?;
    }
    Ok(packet)
}

fn resolve_recipe(
    packet: Option<String>,
    packet_file: Option<PathBuf>,
    registry: &core::registry::Registry,
    max_layers: usize,
) -> Result<Packet, CliError> {
    let (input, path) = match (packet, packet_file) {
        (Some(expression), None) => return parse_expression(&expression, registry, max_layers),
        (None, Some(path)) => {
            let bytes = read_bounded_file(
                &path,
                core::document::DEFAULT_MAX_DOCUMENT_BYTES,
                InputKind::Recipe,
            )?;
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(
                    Kind::Usage,
                    format!("packet document is not UTF-8: {source}"),
                )
            })?;
            (input, Some(path))
        }
        (None, None) => {
            let bytes = read_stdin_bounded(
                core::document::DEFAULT_MAX_DOCUMENT_BYTES,
                InputKind::Recipe,
            )?;
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(Kind::Usage, format!("stdin recipe is not UTF-8: {source}"))
            })?;
            (input, None)
        }
        (Some(_), Some(_)) => unreachable!("clap enforces recipe source conflicts"),
    };
    let trimmed = input.trim_start();
    let format = path
        .as_deref()
        .and_then(document_format_from_path)
        .or_else(|| {
            trimmed
                .starts_with('{')
                .then_some(core::document::Format::Json)
        })
        .or_else(|| {
            (trimmed.starts_with("schema:") || trimmed.starts_with("---"))
                .then_some(core::document::Format::Yaml)
        });
    let parse_document = |format| {
        core::document::Packet::parse_with_limits(
            &input,
            format,
            &core::document::DocumentLimits {
                max_layers,
                ..core::document::DocumentLimits::DEFAULT
            },
        )
    };
    if let Some(format) = format {
        return parse_document(format)
            .and_then(|document| document.to_packet(registry, max_layers))
            .map_err(CliError::classified);
    }
    let mut expression_error = match parse_expression(&input, registry, max_layers) {
        Ok(packet) => return Ok(packet),
        Err(error) => error,
    };
    match parse_document(core::document::Format::Yaml) {
        Ok(document) => document
            .to_packet(registry, max_layers)
            .map_err(CliError::classified),
        Err(error) => {
            expression_error.causes.push(error.to_string());
            Err(expression_error)
        }
    }
}

/// Loads a file into an existing, empty bytes-typed recipe field under the
/// packet input ceiling. Saved documents retain the bytes, independent of the
/// file.
fn apply_payload_file(packet: &mut Packet, spec: &str) -> Result<(), CliError> {
    let syntax = || {
        CliError::new(
            Kind::Usage,
            "--payload-file requires LAYER.FIELD=PATH with a zero-based layer index",
        )
    };
    let (selector, path) = spec.split_once('=').ok_or_else(syntax)?;
    let (layer, field) = selector.trim().split_once('.').ok_or_else(syntax)?;
    let layer_index = layer.parse::<usize>().map_err(|_| syntax())?;
    let field = field.trim().to_ascii_lowercase();
    if field.is_empty() {
        return Err(syntax());
    }
    let packet_len = packet.len();
    let layer = packet.layer_mut(layer_index).ok_or_else(|| {
        CliError::new(
            Kind::Usage,
            format!(
                "--payload-file layer index {layer_index} is outside the recipe's {packet_len} layers"
            ),
        )
    })?;
    let current = layer.field_path(&field).ok_or_else(|| {
        CliError::new(
            Kind::Usage,
            format!("--payload-file field {field} is unknown on layer {layer_index}"),
        )
    })?;
    let core::field::FieldValue::Bytes(current) = current else {
        return Err(CliError::new(
            Kind::Usage,
            format!("--payload-file field {field} on layer {layer_index} is not bytes-typed"),
        ));
    };
    if !current.is_empty() {
        return Err(CliError::new(
            Kind::Usage,
            format!(
                "--payload-file field {field} on layer {layer_index} already holds recipe bytes"
            ),
        ));
    }
    let bytes = read_bounded_file_allow_empty(
        Path::new(path),
        core::document::DEFAULT_MAX_DOCUMENT_BYTES,
        InputKind::Recipe,
    )?;
    layer
        .set_field_path(&field, core::field::FieldValue::Bytes(bytes.into()))
        .map_err(|source| {
            CliError::new(
                Kind::Usage,
                format!(
                    "could not set --payload-file field {field} on layer {layer_index}: {source}"
                ),
            )
        })
}

fn parse_expression(
    input: &str,
    registry: &core::registry::Registry,
    max_layers: usize,
) -> Result<Packet, CliError> {
    core::expression::parse(
        input,
        registry,
        core::expression::Options {
            max_layers,
            ..core::expression::Options::default()
        },
    )
    .map_err(CliError::classified)
}

fn document_format_from_path(path: &Path) -> Option<core::document::Format> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "json" => Some(core::document::Format::Json),
        "yaml" | "yml" => Some(core::document::Format::Yaml),
        _ => None,
    }
}

pub(crate) fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    let bytes = read_bounded_file_allow_empty(path, max_bytes, kind)?;
    if bytes.is_empty() {
        return Err(missing_input_error(kind));
    }
    Ok(bytes)
}

pub(crate) fn read_bounded_file_allow_empty(
    path: &Path,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    read_bounded_allow_empty(open_file(path)?, max_bytes, kind)
}

fn open_file(path: &Path) -> Result<File, CliError> {
    File::open(path).map_err(|source| {
        CliError::caused(
            Kind::Io,
            &FileIo {
                operation: "open",
                path: path.to_owned(),
                source,
            },
        )
    })
}

/// A file operation on an input path, retaining the I/O source so the
/// published error names the file and keeps its cause chain.
#[derive(Debug, thiserror::Error)]
#[error("{operation} {} failed: {source}", .path.display())]
struct FileIo {
    operation: &'static str,
    path: PathBuf,
    #[source]
    source: io::Error,
}

/// A failed read of bounded packet or frame input, retaining the I/O source.
#[derive(Debug, thiserror::Error)]
#[error("read {label} input failed: {source}")]
struct InputRead {
    label: &'static str,
    #[source]
    source: io::Error,
}

/// Reads a complete JSON document file (`--rules-file`, `--udp-profiles`)
/// under `max_bytes`. These are plain documents, not capture streams, so
/// open/read failures are ordinary `io.runtime` errors and an oversized
/// document is a CLI input failure.
pub(crate) fn read_bounded_json_document(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, CliError> {
    let document_io = |operation: &'static str| {
        move |source: io::Error| {
            CliError::caused(
                Kind::Io,
                &FileIo {
                    operation,
                    path: path.to_owned(),
                    source,
                },
            )
        }
    };
    let file = File::open(path).map_err(document_io("open"))?;
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(document_io("read"))?;
    if bytes.len() > max_bytes {
        return Err(CliError::new(
            Kind::Usage,
            format!("document {} exceeds {max_bytes} byte limit", path.display()),
        ));
    }
    Ok(bytes)
}

pub(crate) fn read_stdin_bounded(max_bytes: usize, kind: InputKind) -> Result<Vec<u8>, CliError> {
    let stdin = io::stdin();
    require_redirected_stdin(kind, stdin.is_terminal())?;
    read_bounded(stdin.lock(), max_bytes, kind)
}

pub(crate) fn parse_target(target: String) -> Result<packetcraftr::target::Target, CliError> {
    target
        .parse::<packetcraftr::target::Target>()
        .map_err(CliError::classified)
}

/// Opens a capture reader under its per-item bounds; the aggregate frame and
/// byte ceilings are charged per frame while streaming, not while opening.
fn capture_source(path: &Path) -> Result<Box<dyn Read>, CliError> {
    crate::cancellation::check()?;
    if path == Path::new("-") {
        let stdin = io::stdin();
        require_redirected_stdin(InputKind::Capture, stdin.is_terminal())?;
        Ok(Box::new(stdin.lock()))
    } else {
        Ok(Box::new(open_file(path)?))
    }
}

pub(crate) fn open_capture(
    path: &Path,
    bounds: CaptureReaderBoundsArgs,
) -> Result<Reader<Box<dyn Read>>, CliError> {
    capture_reader(capture_source(path)?, bounds)
}

/// The fingerprint covers the same read stream as the comparison, including
/// compression/container bytes. Publish it only after a successful EOF.
pub(crate) fn open_capture_hashed(
    path: &Path,
    bounds: CaptureReaderBoundsArgs,
) -> Result<(Reader<Box<dyn Read>>, Fingerprint), CliError> {
    let (source, fingerprint) = fingerprint::Hashed::new(capture_source(path)?);
    Ok((capture_reader(source, bounds)?, fingerprint))
}

pub(crate) fn open_capture_file(
    path: &Path,
    bounds: CaptureReaderBoundsArgs,
) -> Result<Reader<Box<dyn Read>>, CliError> {
    capture_reader(open_file(path)?, bounds)
}

/// Validate and preserve a bounded source in an anonymous seekable snapshot.
/// Callers can analyze and copy identical records, including redirected stdin.
pub(crate) fn snapshot_capture<R: Read>(
    input: &mut Reader<R>,
    bounds: CaptureReaderBoundsArgs,
    limits: core::capture_file::Limits,
) -> Result<Reader<File>, CliError> {
    use core::capture_file;
    crate::cancellation::check()?;
    let snapshot = tempfile::tempfile()
        .map_err(capture_file::Error::from)
        .map_err(CliError::classified)?;
    let (snapshot, _) = capture_file::rewrite(
        input,
        io::BufWriter::with_capacity(64 * 1024, snapshot),
        limits,
    )
    .map_err(CliError::classified)?;
    let mut snapshot = snapshot
        .into_inner()
        .map_err(|error| CliError::classified(capture_file::Error::from(error.into_error())))?;
    std::io::Seek::rewind(&mut snapshot)
        .map_err(capture_file::Error::from)
        .map_err(CliError::classified)?;
    crate::cancellation::check()?;
    Reader::with_options(
        snapshot,
        ReaderOptions {
            max_size: bounds.max_frame_bytes,
            max_interfaces_per_section: bounds.max_interfaces,
            ..Default::default()
        },
    )
    .map(|reader| {
        crate::invocation::reader(reader.with_cancellation(crate::cancellation::signal().clone()))
    })
    .map_err(CliError::classified)
}

fn capture_reader<R: Read + 'static>(
    source: R,
    bounds: CaptureReaderBoundsArgs,
) -> Result<Reader<Box<dyn Read>>, CliError> {
    crate::cancellation::check()?;
    let source: Box<dyn Read> = Box::new(
        core::capture_file::compression::Input::new(
            source,
            core::capture_file::compression::Limits {
                max_decoded_bytes: bounds.max_decoded_bytes,
                max_encoded_bytes: bounds.max_encoded_bytes,
                ..Default::default()
            },
        )
        .map_err(CliError::classified)?,
    );
    let reader = Reader::with_options(
        source,
        ReaderOptions {
            max_size: bounds.max_frame_bytes,
            max_interfaces_per_section: bounds.max_interfaces,
            ..ReaderOptions::default()
        },
    )
    .map_err(CliError::classified)?;
    crate::cancellation::check()?;
    Ok(crate::invocation::reader(
        reader.with_cancellation(crate::cancellation::signal().clone()),
    ))
}

fn read_bounded(reader: impl Read, max_bytes: usize, kind: InputKind) -> Result<Vec<u8>, CliError> {
    let bytes = read_bounded_allow_empty(reader, max_bytes, kind)?;
    if bytes.is_empty() {
        return Err(missing_input_error(kind));
    }
    Ok(bytes)
}

fn read_bounded_allow_empty(
    reader: impl Read,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            CliError::caused(
                Kind::Io,
                &InputRead {
                    label: kind.label(),
                    source,
                },
            )
        })?;
    if bytes.len() > max_bytes {
        return Err(kind.oversized_error(bytes.len(), max_bytes));
    }
    Ok(bytes)
}

pub(crate) fn validate_capture_stream_limits(
    limits: OfflineCaptureLimitsArgs,
) -> Result<(), CliError> {
    let OfflineCaptureLimitsArgs {
        max_frames,
        max_bytes,
        reader:
            CaptureReaderBoundsArgs {
                max_decoded_bytes: _,
                max_encoded_bytes: _,
                max_frame_bytes,
                max_interfaces,
            },
    } = limits;
    if max_frames == 0 || max_bytes == 0 || max_frame_bytes == 0 || max_interfaces == 0 {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_limit",
                Kind::Usage,
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
                Kind::Usage,
                Some("set max-frame-bytes no higher than the aggregate max-bytes budget"),
            ),
            format!("max-frame-bytes {max_frame_bytes} exceeds max-bytes {max_bytes}"),
            Vec::new(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn bounded_reads_distinguish_empty_exact_and_oversized_input() {
        assert_eq!(
            read_bounded_allow_empty(Cursor::new([]), 0, InputKind::Recipe)
                .expect("empty input is allowed"),
            Vec::<u8>::new(),
        );
        assert_eq!(
            read_bounded(Cursor::new(b"abcd"), 4, InputKind::Recipe)
                .expect("exact limit is accepted"),
            b"abcd",
        );

        let empty = read_bounded(Cursor::new([]), 4, InputKind::Recipe)
            .expect_err("required input is empty");
        assert_eq!(empty.exit_code(), 2);
        assert!(empty.message.contains("non-empty stdin"));

        let oversized = read_bounded_allow_empty(Cursor::new(b"abcde"), 4, InputKind::Recipe)
            .expect_err("limit is enforced");
        assert_eq!(oversized.exit_code(), 2);
        assert_eq!(oversized.message, "packet input exceeds 4 byte limit");

        assert_eq!(
            read_bounded_allow_empty(Cursor::new([]), usize::MAX, InputKind::Recipe)
                .expect("the maximum limit accepts empty input"),
            Vec::<u8>::new(),
        );

        let oversized_frame = read_bounded_allow_empty(Cursor::new(b"abcde"), 4, InputKind::Frame)
            .expect_err("the decode byte budget is enforced while reading");
        assert_eq!(oversized_frame.exit_code(), 6);
        assert_eq!(
            oversized_frame.classification.code,
            "policy.decode_resource_limit"
        );
    }

    /// A reader that dies partway through is an I/O failure, not a malformed
    /// document: exit 5, with the byte count that made it through discarded.
    #[test]
    fn a_reader_that_fails_mid_read_is_reported_as_an_io_failure() {
        struct BrokenReader {
            delivered: bool,
        }

        impl Read for BrokenReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.delivered {
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                }
                self.delivered = true;
                let written = buffer.len().min(2);
                buffer
                    .get_mut(..written)
                    .expect("the truncated prefix is in bounds")
                    .fill(b'a');
                Ok(written)
            }
        }

        for kind in [InputKind::Recipe, InputKind::Frame] {
            let required = read_bounded(BrokenReader { delivered: false }, 64, kind)
                .expect_err("a broken reader must fail");
            assert_eq!(required.exit_code(), 5, "{kind:?}");
            assert!(
                required.message.starts_with("read "),
                "{}",
                required.message
            );
            assert!(
                required.message.to_lowercase().contains("broken pipe"),
                "{}",
                required.message
            );
            assert!(
                matches!(&required.causes[..], [cause] if cause.to_lowercase().contains("broken pipe")),
                "{:?}",
                required.causes
            );

            let optional = read_bounded_allow_empty(BrokenReader { delivered: false }, 64, kind)
                .expect_err("a broken reader must fail even where empty input is allowed");
            assert_eq!(optional.exit_code(), 5, "{kind:?}");
            assert!(
                optional.message.starts_with("read "),
                "{}",
                optional.message
            );
        }
    }

    #[test]
    fn terminal_input_decision_is_immediate_and_command_specific() {
        let recipe = require_redirected_stdin(InputKind::Recipe, true)
            .expect_err("recipe terminal input must be rejected");
        assert_eq!(recipe.classification.code, "cli.input_source");
        assert_eq!(recipe.exit_code(), 2);
        assert!(recipe.message.contains("--packet"));
        assert!(recipe.message.contains("--packet-file"));
        assert!(recipe.classification.remediation.is_some());

        let frame = require_redirected_stdin(InputKind::Frame, true)
            .expect_err("frame terminal input must be rejected");
        assert_eq!(frame.classification.code, "cli.input_source");
        assert_eq!(frame.exit_code(), 2);
        assert!(frame.message.contains("--hex"));
        assert!(frame.message.contains("--file"));
        assert!(!frame.message.contains("--packet"));
        assert!(!frame.message.contains("--packet-file"));
        assert!(frame.classification.remediation.is_some());

        let capture = require_redirected_stdin(InputKind::Capture, true)
            .expect_err("capture terminal input must be rejected");
        assert_eq!(capture.classification.code, "cli.input_source");
        assert_eq!(capture.exit_code(), 2);
        assert!(capture.message.contains("capture path"));
        assert!(capture.message.contains("-"));
        assert!(capture.classification.remediation.is_some());

        require_redirected_stdin(InputKind::Recipe, false)
            .expect("redirected recipe input must remain available");
        require_redirected_stdin(InputKind::Frame, false)
            .expect("redirected frame input must remain available");
        require_redirected_stdin(InputKind::Capture, false)
            .expect("redirected capture input must remain available");
    }

    #[test]
    fn capture_stream_limits_reject_each_zero_and_cross_limit_case() {
        let bounds =
            |max_frames, max_bytes, max_frame_bytes, max_interfaces| OfflineCaptureLimitsArgs {
                max_frames,
                max_bytes,
                reader: CaptureReaderBoundsArgs {
                    max_encoded_bytes: 256 * 1024 * 1024,
                    max_decoded_bytes: 256 * 1024 * 1024,
                    max_frame_bytes,
                    max_interfaces,
                },
            };

        for limits in [(0, 1, 1, 1), (1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0)] {
            let error =
                validate_capture_stream_limits(bounds(limits.0, limits.1, limits.2, limits.3))
                    .expect_err("every capture bound must be non-zero");
            assert_eq!(error.exit_code(), 2, "limits={limits:?}");
            assert_eq!(error.classification.code, "cli.capture_limit");
        }

        let error = validate_capture_stream_limits(bounds(1, 7, 8, 1))
            .expect_err("one frame cannot exceed the aggregate byte budget");
        assert_eq!(error.message, "max-frame-bytes 8 exceeds max-bytes 7");
        validate_capture_stream_limits(bounds(1, 8, 8, 1)).expect("equal byte bounds are valid");
    }

    #[test]
    fn document_extensions_are_case_insensitive_and_explicit() {
        use packetcraftr_core::document::Format;

        for (path, expected) in [
            ("packet.json", Some(Format::Json)),
            ("packet.JSON", Some(Format::Json)),
            ("packet.yaml", Some(Format::Yaml)),
            ("packet.yml", Some(Format::Yaml)),
            ("packet.txt", None),
            ("packet", None),
        ] {
            assert_eq!(
                document_format_from_path(Path::new(path)),
                expected,
                "{path}"
            );
        }
    }
}
