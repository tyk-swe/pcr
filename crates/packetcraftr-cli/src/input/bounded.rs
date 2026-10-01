// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};

use packetcraftr_core as core;
use packetcraftr_core::error::{Classification, Classified, Kind};

use crate::errors::CliError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputKind {
    Recipe,
    Frame,
    /// Hexadecimal text that decodes to frame bytes.
    FrameHex,
    Payload,
    Capture,
}

impl InputKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Recipe => "packet",
            Self::Frame => "frame",
            Self::FrameHex => "frame hex text",
            Self::Payload => "UDP payload",
            Self::Capture => "capture",
        }
    }

    const fn options(self) -> &'static str {
        match self {
            Self::Recipe => "--packet, --packet-file, or redirect non-empty stdin",
            Self::Frame => "--hex, --file, or redirect non-empty stdin",
            Self::FrameHex => "--hex, --hex-file, --file, or redirect non-empty stdin",
            Self::Payload => "--udp-payload-hex or --udp-payload-file",
            Self::Capture => "a capture path, or use - with redirected capture stdin",
        }
    }

    const fn remediation(self) -> &'static str {
        match self {
            Self::Recipe => {
                "provide --packet, --packet-file, or pipe a non-empty packet recipe to stdin"
            }
            Self::Frame => "provide --hex, --file, or pipe non-empty frame bytes to stdin",
            Self::FrameHex => {
                "provide --hex, --hex-file, --file, or pipe non-empty hexadecimal text to stdin"
            }
            Self::Payload => "provide --udp-payload-hex or --udp-payload-file",
            Self::Capture => "provide a capture path or pipe PCAP/PCAPNG bytes with - as the path",
        }
    }

    fn oversized_error(self, actual: usize, limit: usize) -> CliError {
        match self {
            Self::Recipe | Self::Payload | Self::Capture => CliError::new(
                Kind::Usage,
                format!("{} input exceeds {limit} byte limit", self.label()),
            ),
            Self::Frame => {
                CliError::classified(core::decode::Error::PacketSizeLimit { actual, limit })
            }
            // The text bound derives from the packet budget, so it shares that classification.
            Self::FrameHex => CliError::from_classification(
                core::decode::Error::PacketSizeLimit { actual, limit }.classification(),
                format!("{} input exceeds {limit} byte limit", self.label()),
                Vec::new(),
            ),
        }
    }
}

pub(crate) fn missing_input_error(kind: InputKind) -> CliError {
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

pub(super) fn require_redirected_stdin(
    kind: InputKind,
    stdin_is_terminal: bool,
) -> Result<(), CliError> {
    if stdin_is_terminal {
        Err(missing_input_error(kind))
    } else {
        Ok(())
    }
}

pub(crate) fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    require_non_empty(read_bounded_file_allow_empty(path, max_bytes, kind)?, kind)
}

pub(crate) fn read_bounded_file_allow_empty(
    path: &Path,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    read_bounded_allow_empty(open_file(path)?, max_bytes, kind)
}

pub(super) fn open_file(path: &Path) -> Result<File, CliError> {
    File::open(path).map_err(|source| file_io_error("open", path, source))
}

fn file_io_error(operation: &'static str, path: &Path, source: io::Error) -> CliError {
    CliError::caused(
        Kind::Io,
        &FileIo {
            operation,
            path: path.to_owned(),
            source,
        },
    )
}

#[derive(Debug, thiserror::Error)]
#[error("{operation} {} failed", .path.display())]
struct FileIo {
    operation: &'static str,
    path: PathBuf,
    #[source]
    source: io::Error,
}

#[derive(Debug, thiserror::Error)]
#[error("read {label} input failed")]
struct InputRead {
    label: &'static str,
    #[source]
    source: io::Error,
}

/// Text bytes that can hold `max_packet_size` decoded bytes: at most a digit pair, a prefix or
/// separator, and slack per byte, plus surrounding whitespace.
pub(crate) fn hex_text_limit(max_packet_size: usize) -> usize {
    max_packet_size.saturating_mul(4).saturating_add(4096)
}

pub(crate) fn read_bounded_json_document(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, CliError> {
    let bytes = read_capped(open_file(path)?, max_bytes)
        .map_err(|source| file_io_error("read", path, source))?;
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

fn read_bounded(reader: impl Read, max_bytes: usize, kind: InputKind) -> Result<Vec<u8>, CliError> {
    require_non_empty(read_bounded_allow_empty(reader, max_bytes, kind)?, kind)
}

fn require_non_empty(bytes: Vec<u8>, kind: InputKind) -> Result<Vec<u8>, CliError> {
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
    let bytes = read_capped(reader, max_bytes).map_err(|source| {
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

/// Reads at most `max_bytes + 1` bytes, so a caller can tell a full read from an oversized one.
fn read_capped(reader: impl Read, max_bytes: usize) -> io::Result<Vec<u8>> {
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    reader.take(read_limit).read_to_end(&mut bytes)?;
    Ok(bytes)
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

        let oversized_payload =
            read_bounded_allow_empty(Cursor::new(b"abcde"), 4, InputKind::Payload)
                .expect_err("the UDP payload limit is a usage error");
        assert_eq!(oversized_payload.exit_code(), 2);
        assert_eq!(oversized_payload.classification.code, "cli.error");
        assert_eq!(
            oversized_payload.message,
            "UDP payload input exceeds 4 byte limit"
        );

        let oversized_frame = read_bounded_allow_empty(Cursor::new(b"abcde"), 4, InputKind::Frame)
            .expect_err("the decode byte budget is enforced while reading");
        assert_eq!(oversized_frame.exit_code(), 6);
        assert_eq!(
            oversized_frame.classification.code,
            "policy.decode_resource_limit"
        );
    }

    #[test]
    fn hex_text_is_bounded_by_the_packet_budget_with_its_classification() {
        assert_eq!(hex_text_limit(10), 4136);
        assert_eq!(hex_text_limit(usize::MAX), usize::MAX);

        let oversized = read_bounded_allow_empty(Cursor::new(b"abcde"), 4, InputKind::FrameHex)
            .expect_err("the text bound is enforced while reading");
        assert_eq!(oversized.exit_code(), 6);
        assert_eq!(
            oversized.classification.code,
            "policy.decode_resource_limit"
        );
        assert_eq!(
            oversized.message,
            "frame hex text input exceeds 4 byte limit"
        );

        let terminal = require_redirected_stdin(InputKind::FrameHex, true)
            .expect_err("terminal stdin is rejected");
        assert_eq!(terminal.exit_code(), 2);
        assert!(terminal.message.contains("--hex-file"));
    }

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

        for kind in [InputKind::Recipe, InputKind::Frame, InputKind::Payload] {
            let required = read_bounded(BrokenReader { delivered: false }, 64, kind)
                .expect_err("a broken reader must fail");
            assert_eq!(required.exit_code(), 5, "{kind:?}");
            assert_eq!(
                required.message,
                format!("read {} input failed", kind.label())
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
    fn json_documents_accept_the_exact_limit_and_refuse_oversized_or_missing_files() {
        let directory = tempfile::tempdir().expect("temporary directory must open");
        let document = directory.path().join("document.json");
        std::fs::write(&document, b"abcd").expect("fixture document must write");

        assert_eq!(
            read_bounded_json_document(&document, 4).expect("exact limit is accepted"),
            b"abcd",
        );

        let oversized = read_bounded_json_document(&document, 3).expect_err("limit is enforced");
        assert_eq!(oversized.exit_code(), 2);
        assert_eq!(
            oversized.message,
            format!("document {} exceeds 3 byte limit", document.display())
        );

        let missing = directory.path().join("missing.json");
        let missing_error =
            read_bounded_json_document(&missing, 4).expect_err("a missing document must fail");
        assert_eq!(missing_error.exit_code(), 5);
        assert_eq!(
            missing_error.message,
            format!("open {} failed", missing.display())
        );
        assert_eq!(missing_error.causes.len(), 1, "{:?}", missing_error.causes);
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
}
