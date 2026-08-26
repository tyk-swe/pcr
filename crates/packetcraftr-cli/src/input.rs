// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::path::Path;

use packetcraftr::{
    analysis::pcap::{Reader, ReaderOptions},
    core::error::{Classification, Kind},
    core::{self, Packet},
};

use super::command_options::{OfflineCaptureLimitsArgs, RecipeArgs};
use super::errors::CliError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputKind {
    Recipe,
    Frame,
}

impl InputKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Recipe => "packet",
            Self::Frame => "frame",
        }
    }

    const fn options(self) -> &'static str {
        match self {
            Self::Recipe => "--packet, --packet-file, or redirect non-empty stdin",
            Self::Frame => "--hex, --file, or redirect non-empty stdin",
        }
    }

    const fn remediation(self) -> &'static str {
        match self {
            Self::Recipe => {
                "provide --packet, --packet-file, or pipe a non-empty packet recipe to stdin"
            }
            Self::Frame => "provide --hex, --file, or pipe non-empty frame bytes to stdin",
        }
    }
}

fn missing_input_error(kind: InputKind) -> CliError {
    CliError::from_classification(
        Classification::new("cli.input_source", Kind::Cli, Some(kind.remediation())),
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

pub(super) fn read_recipe(
    arguments: RecipeArgs,
    registry: &core::registry::Registry,
) -> Result<Packet, CliError> {
    let RecipeArgs {
        packet,
        packet_file,
    } = arguments;

    let (input, path) = match (packet, packet_file) {
        (Some(expression), None) => return parse_expression(&expression, registry),
        (None, Some(path)) => {
            let bytes = read_bounded_file(
                &path,
                core::document::DEFAULT_MAX_DOCUMENT_BYTES,
                InputKind::Recipe,
            )?;
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(2, format!("packet document is not UTF-8: {source}"))
            })?;
            (input, Some(path))
        }
        (None, None) => {
            let bytes = read_stdin_bounded(
                core::document::DEFAULT_MAX_DOCUMENT_BYTES,
                InputKind::Recipe,
            )?;
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(2, format!("stdin recipe is not UTF-8: {source}"))
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
    if let Some(format) = format {
        return core::document::Packet::parse_with_resource_limits(
            &input,
            format,
            core::document::DEFAULT_MAX_DOCUMENT_BYTES,
            core::build::DEFAULT_MAX_LAYERS,
            core::document::DEFAULT_MAX_DOCUMENT_NESTING,
        )
        .and_then(|document| document.to_packet(registry, core::build::DEFAULT_MAX_LAYERS))
        .map_err(|source| CliError::new(2, source.to_string()));
    }
    parse_expression(&input, registry)
}

fn parse_expression(input: &str, registry: &core::registry::Registry) -> Result<Packet, CliError> {
    core::expression::parse(input, registry, core::expression::Options::default())
        .map_err(|source| CliError::new(2, source.to_string()))
}

fn document_format_from_path(path: &Path) -> Option<core::document::Format> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "json" => Some(core::document::Format::Json),
        "yaml" | "yml" => Some(core::document::Format::Yaml),
        _ => None,
    }
}

pub(super) fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    let file = File::open(path)
        .map_err(|source| CliError::new(5, format!("open {} failed: {source}", path.display())))?;
    read_bounded(file, max_bytes, kind)
}

pub(super) fn read_stdin_bounded(max_bytes: usize, kind: InputKind) -> Result<Vec<u8>, CliError> {
    let stdin = io::stdin();
    require_redirected_stdin(kind, stdin.is_terminal())?;
    read_bounded(stdin.lock(), max_bytes, kind)
}

pub(super) fn parse_target(target: String) -> Result<packetcraftr::target::Target, CliError> {
    target
        .parse::<packetcraftr::target::Target>()
        .map_err(CliError::classified)
}

pub(super) fn open_capture(
    path: &Path,
    limits: OfflineCaptureLimitsArgs,
) -> Result<Reader<File>, CliError> {
    let file = File::open(path)
        .map_err(|source| CliError::new(5, format!("open {} failed: {source}", path.display())))?;
    Reader::with_options(
        file,
        ReaderOptions {
            max_size: limits.max_frame_bytes,
            max_interfaces_per_section: limits.max_interfaces,
            ..ReaderOptions::default()
        },
    )
    .map_err(CliError::classified)
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
    let read_limit = max_bytes
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| {
            CliError::new(
                70,
                format!("{} input byte limit cannot be represented", kind.label()),
            )
        })?;
    let mut bytes = Vec::new();
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            CliError::new(5, format!("read {} input failed: {source}", kind.label()))
        })?;
    if bytes.len() > max_bytes {
        return Err(CliError::new(
            2,
            format!("{} input exceeds {max_bytes} byte limit", kind.label()),
        ));
    }
    Ok(bytes)
}

pub(super) fn validate_capture_stream_limits(
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
        assert_eq!(empty.exit_code, 2);
        assert!(empty.message.contains("non-empty stdin"));

        let oversized = read_bounded_allow_empty(Cursor::new(b"abcde"), 4, InputKind::Recipe)
            .expect_err("limit is enforced");
        assert_eq!(oversized.exit_code, 2);
        assert_eq!(oversized.message, "packet input exceeds 4 byte limit");

        let unrepresentable =
            read_bounded_allow_empty(Cursor::new([]), usize::MAX, InputKind::Recipe)
                .expect_err("the sentinel byte must be representable");
        assert_eq!(unrepresentable.exit_code, 70);
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
            assert_eq!(required.exit_code, 5, "{kind:?}");
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

            let optional = read_bounded_allow_empty(BrokenReader { delivered: false }, 64, kind)
                .expect_err("a broken reader must fail even where empty input is allowed");
            assert_eq!(optional.exit_code, 5, "{kind:?}");
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
        assert_eq!(recipe.exit_code, 2);
        assert!(recipe.message.contains("--packet"));
        assert!(recipe.message.contains("--packet-file"));
        assert!(recipe.classification.remediation.is_some());

        let frame = require_redirected_stdin(InputKind::Frame, true)
            .expect_err("frame terminal input must be rejected");
        assert_eq!(frame.classification.code, "cli.input_source");
        assert_eq!(frame.exit_code, 2);
        assert!(frame.message.contains("--hex"));
        assert!(frame.message.contains("--file"));
        assert!(!frame.message.contains("--packet"));
        assert!(!frame.message.contains("--packet-file"));
        assert!(frame.classification.remediation.is_some());

        require_redirected_stdin(InputKind::Recipe, false)
            .expect("redirected recipe input must remain available");
        require_redirected_stdin(InputKind::Frame, false)
            .expect("redirected frame input must remain available");
    }

    #[test]
    fn capture_stream_limits_reject_each_zero_and_cross_limit_case() {
        for limits in [(0, 1, 1, 1), (1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0)] {
            let error = validate_capture_stream_limits(limits.0, limits.1, limits.2, limits.3)
                .expect_err("every capture bound must be non-zero");
            assert_eq!(error.exit_code, 2, "limits={limits:?}");
            assert_eq!(error.classification.code, "cli.capture_limit");
        }

        let error = validate_capture_stream_limits(1, 7, 8, 1)
            .expect_err("one frame cannot exceed the aggregate byte budget");
        assert_eq!(error.message, "max-frame-bytes 8 exceeds max-bytes 7");
        validate_capture_stream_limits(1, 8, 8, 1).expect("equal byte bounds are valid");
    }

    #[test]
    fn document_extensions_are_case_insensitive_and_explicit() {
        use packetcraftr::core::document::Format;

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
