// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};

use packetcraftr_core as core;
use packetcraftr_core::error::{Classification, Classified, Kind};

use super::manifest;
use super::source::{self, Source, interrupted_or};
use crate::errors::CliError;
use crate::invocation::Control;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputKind {
    Recipe,
    Frame,
    /// Hexadecimal text that decodes to frame bytes.
    FrameHex,
    Payload,
    /// The server reply a generated conversation carries.
    SessionResponse,
    Capture,
    Manifest,
    UdpProfiles,
    ServiceDocument,
    OsDocument,
    SecurityDocument,
}

impl InputKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Recipe => "packet",
            Self::Frame => "frame",
            Self::FrameHex => "frame hex text",
            Self::Payload => "UDP payload",
            Self::SessionResponse => "session response",
            Self::Capture => "capture",
            Self::Manifest => "target manifest",
            Self::UdpProfiles => "UDP profiles",
            Self::ServiceDocument => "service identification document",
            Self::OsDocument => "OS fingerprint document",
            Self::SecurityDocument => "security JSON document",
        }
    }

    const fn options(self) -> &'static str {
        match self {
            Self::Recipe => "--packet, --packet-file, or redirect non-empty stdin",
            Self::Frame => "--hex, --file, or redirect non-empty stdin",
            Self::FrameHex => "--hex, --hex-file, --file, or redirect non-empty stdin",
            Self::Payload => "--udp-payload-hex or --udp-payload-file",
            Self::SessionResponse => "--session-response-file",
            Self::Capture => "a capture path, or use - with redirected capture stdin",
            Self::Manifest => {
                "--targets-file or --exclude-file PATH, or - with redirected manifest stdin"
            }
            Self::UdpProfiles => "--udp-profiles PATH, or - with redirected document stdin",
            Self::ServiceDocument => "--corpus PATH or --exclusions PATH",
            Self::OsDocument => "--corpus PATH",
            Self::SecurityDocument => "a document path, or - with redirected JSON stdin",
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
            Self::SessionResponse => "provide a non-empty --session-response-file",
            Self::Capture => "provide a capture path or pipe PCAP/PCAPNG bytes with - as the path",
            Self::Manifest => {
                "provide a --targets-file or --exclude-file path, or pipe a manifest with -"
            }
            Self::UdpProfiles => {
                "provide a --udp-profiles path, or pipe the document to stdin with -"
            }
            Self::ServiceDocument => "provide a non-empty JSON service identification document",
            Self::OsDocument => "provide a non-empty JSON OS fingerprint document",
            Self::SecurityDocument => "provide a JSON document path or redirect JSON stdin with -",
        }
    }

    fn oversized_error(self, actual: usize, limit: usize) -> CliError {
        match self {
            Self::Recipe
            | Self::Payload
            | Self::SessionResponse
            | Self::Capture
            | Self::Manifest
            | Self::UdpProfiles
            | Self::ServiceDocument
            | Self::OsDocument
            | Self::SecurityDocument => CliError::new(
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
        Classification::new(
            packetcraftr_core::error::Code::CliInputSource,
            Kind::Usage,
            Some(kind.remediation()),
        ),
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
    control: &Control,
    path: &Path,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    require_non_empty(
        read_bounded_file_allow_empty(control, path, max_bytes, kind)?,
        kind,
    )
    .map_err(|error| error.with_input(path.display()))
}

pub(crate) fn read_bounded_file_allow_empty(
    control: &Control,
    path: &Path,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    let bytes = read_file_capped(control, path, max_bytes)?;
    require_bounded(bytes, max_bytes, kind).map_err(|error| error.with_input(path.display()))
}

pub(super) fn open_file(control: &Control, path: &Path) -> Result<Source, CliError> {
    source::open(control, path).map_err(|source| file_io_error("open", path, source))
}

pub(super) fn redirected_stdin(control: &Control, kind: InputKind) -> Result<Source, CliError> {
    require_redirected_stdin(kind, io::stdin().is_terminal())?;
    source::stdin(control).map_err(|source| input_read_error(kind, source))
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
#[error("read {label} input from stdin failed")]
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
    control: &Control,
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, CliError> {
    let bytes = read_file_capped(control, path, max_bytes)?;
    if bytes.len() > max_bytes {
        return Err(CliError::new(
            Kind::Usage,
            format!("document {} exceeds {max_bytes} byte limit", path.display()),
        ));
    }
    Ok(bytes)
}

pub(crate) fn read_stdin_bounded(
    control: &Control,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    require_non_empty(
        read_stdin_bounded_allow_empty(control, max_bytes, kind)?,
        kind,
    )
}

fn read_stdin_bounded_allow_empty(
    control: &Control,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    require_bounded(
        read_stdin_capped(control, max_bytes, kind)?,
        max_bytes,
        kind,
    )
}

pub(crate) fn read_document(
    control: &Control,
    path: &Path,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    if manifest::is_stdin(path) {
        read_stdin_bounded(control, max_bytes, kind)
    } else {
        read_bounded_file(control, path, max_bytes, kind)
    }
}

pub(crate) fn read_document_allow_empty(
    control: &Control,
    path: &Path,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    if manifest::is_stdin(path) {
        read_stdin_bounded_allow_empty(control, max_bytes, kind)
    } else {
        read_bounded_file_allow_empty(control, path, max_bytes, kind)
    }
}

fn require_non_empty(bytes: Vec<u8>, kind: InputKind) -> Result<Vec<u8>, CliError> {
    if bytes.is_empty() {
        return Err(missing_input_error(kind));
    }
    Ok(bytes)
}

fn require_bounded(bytes: Vec<u8>, max_bytes: usize, kind: InputKind) -> Result<Vec<u8>, CliError> {
    if bytes.len() > max_bytes {
        return Err(kind.oversized_error(bytes.len(), max_bytes));
    }
    Ok(bytes)
}

/// Reads at most `max_bytes + 1` bytes of `path`, leaving the oversize decision to the caller.
pub(crate) fn read_file_capped(
    control: &Control,
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, CliError> {
    read_file_reader_capped(open_file(control, path)?, path, max_bytes)
        .map_err(|error| interrupted_or(control, error))
}

fn read_file_reader_capped(
    reader: impl Read,
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, CliError> {
    read_capped(reader, max_bytes).map_err(|source| file_io_error("read", path, source))
}

/// Reads at most `max_bytes + 1` bytes of redirected stdin, leaving the oversize decision to the
/// caller.
pub(crate) fn read_stdin_capped(
    control: &Control,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    read_stdin_reader_capped(redirected_stdin(control, kind)?, max_bytes, kind)
        .map_err(|error| interrupted_or(control, error))
}

fn read_stdin_reader_capped(
    reader: impl Read,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    read_capped(reader, max_bytes).map_err(|source| input_read_error(kind, source))
}

fn input_read_error(kind: InputKind, source: io::Error) -> CliError {
    CliError::caused(
        Kind::Io,
        &InputRead {
            label: kind.label(),
            source,
        },
    )
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
    use super::*;

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected read failure"))
        }
    }

    #[test]
    fn read_errors_preserve_source_and_cause() {
        let path = Path::new("inputs/targets.txt");
        let error = read_file_reader_capped(FailingReader, path, 16).unwrap_err();
        assert!(error.message.contains(&path.display().to_string()));
        assert_eq!(error.classification.kind, Kind::Io);
        assert_eq!(error.causes, ["injected read failure"]);

        let error = read_stdin_reader_capped(FailingReader, 16, InputKind::Manifest).unwrap_err();
        assert!(error.message.contains("stdin"));
        assert_eq!(error.causes, ["injected read failure"]);
    }

    #[test]
    fn file_errors_preserve_paths_and_codes() {
        let control = &source::test_control(None, Default::default());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("frame.bin");
        let error = read_bounded_file(control, &path, 1, InputKind::Frame).unwrap_err();
        assert_eq!(error.classification.kind, Kind::Io);
        assert!(error.message.contains(&path.display().to_string()));
        assert!(!error.causes.is_empty());

        std::fs::write(&path, b"ab").unwrap();
        let error = read_bounded_file(control, &path, 1, InputKind::Frame).unwrap_err();
        assert_eq!(
            error.classification,
            core::decode::Error::PacketSizeLimit {
                actual: 2,
                limit: 1
            }
            .classification()
        );
        assert!(error.message.contains(&path.display().to_string()));

        std::fs::write(&path, b"").unwrap();
        let error = read_bounded_file(control, &path, 1, InputKind::Frame).unwrap_err();
        assert_eq!(error.classification.code.as_str(), "cli.input_source");
        assert!(error.message.contains(&path.display().to_string()));
    }

    #[test]
    fn empty_document_is_rejected_from_a_file() {
        let control = &source::test_control(None, Default::default());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty.json");
        std::fs::write(&path, b"").unwrap();

        let error = read_document(control, &path, 16, InputKind::SecurityDocument).unwrap_err();
        assert_eq!(error.classification.code.as_str(), "cli.input_source");
        assert!(
            error
                .message
                .contains("security JSON document input is required"),
            "{}",
            error.message
        );
        assert!(error.message.contains(&path.display().to_string()));

        assert!(
            read_document_allow_empty(control, &path, 16, InputKind::Payload)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn documents_return_exact_bytes_and_reject_oversized_files() {
        let control = &source::test_control(None, Default::default());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("document.json");
        std::fs::write(&path, b"{\"a\":1}").unwrap();

        assert_eq!(
            read_document(control, &path, 16, InputKind::SecurityDocument).unwrap(),
            b"{\"a\":1}"
        );
        assert_eq!(
            read_document_allow_empty(control, &path, 16, InputKind::Payload).unwrap(),
            b"{\"a\":1}"
        );

        std::fs::write(&path, b"0123456789abcdefg").unwrap();

        let error = read_document(control, &path, 16, InputKind::SecurityDocument).unwrap_err();
        assert_eq!(error.classification.kind, Kind::Usage);
        assert!(
            error
                .message
                .contains("security JSON document input exceeds 16 byte limit"),
            "{}",
            error.message
        );
        assert!(error.message.contains(&path.display().to_string()));

        let error = read_document_allow_empty(control, &path, 16, InputKind::Payload).unwrap_err();
        assert_eq!(error.classification.kind, Kind::Usage);
        assert!(
            error
                .message
                .contains("UDP payload input exceeds 16 byte limit"),
            "{}",
            error.message
        );
        assert!(error.message.contains(&path.display().to_string()));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn stalled_fifo_reports_invocation_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("document.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success(), "mkfifo failed: {status:?}");
        let control = source::test_control(
            Some(std::time::Duration::from_millis(200)),
            Default::default(),
        );

        let error = read_document(&control, &fifo, 16, InputKind::SecurityDocument).unwrap_err();

        let expected = control.check().unwrap_err();
        assert_eq!(error.classification, expected.classification);
        assert_eq!(error.exit_code(), expected.exit_code());
        assert!(
            error.message.starts_with("operation took "),
            "{}",
            error.message
        );
        assert!(error.message.ends_with(" budget"), "{}", error.message);
    }
}
