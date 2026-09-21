// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded input reads and command-specific source diagnostics.

mod capture;
mod fingerprint;
mod recipe;
pub(crate) use capture::{
    open_capture, open_capture_file, open_capture_hashed, snapshot_capture,
    validate_capture_stream_limits,
};
pub(crate) use fingerprint::Fingerprint;
pub(crate) use recipe::read_recipe;

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};

use packetcraftr_core as core;
use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Kind;

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
                Kind::Cli,
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

pub(crate) fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    read_bounded(open_file(path)?, max_bytes, kind)
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
        CliError::new(
            Kind::Io,
            format!("open {} failed: {source}", path.display()),
        )
    })
}

/// A file operation on a document path, retaining the I/O source so the
/// published error names the file and keeps its cause chain.
#[derive(Debug, thiserror::Error)]
#[error("{operation} {} failed: {source}", .path.display())]
struct DocumentIo {
    operation: &'static str,
    path: PathBuf,
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
                &DocumentIo {
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
            Kind::Cli,
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
            CliError::new(
                Kind::Io,
                format!("read {} input failed: {source}", kind.label()),
            )
        })?;
    if bytes.len() > max_bytes {
        return Err(kind.oversized_error(bytes.len(), max_bytes));
    }
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
}
