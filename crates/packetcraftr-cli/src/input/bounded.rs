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
        .map_err(|error| error.with_input(path.display()))
}

pub(crate) fn read_bounded_file_allow_empty(
    path: &Path,
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    let bytes = read_file_capped(path, max_bytes)?;
    require_bounded(bytes, max_bytes, kind).map_err(|error| error.with_input(path.display()))
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

pub(crate) fn read_stdin_bounded_allow_empty(
    max_bytes: usize,
    kind: InputKind,
) -> Result<Vec<u8>, CliError> {
    let stdin = io::stdin();
    require_redirected_stdin(kind, stdin.is_terminal())?;
    read_bounded_allow_empty(stdin.lock(), max_bytes, kind)
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
    let bytes = read_capped(reader, max_bytes).map_err(|source| input_read_error(kind, source))?;
    require_bounded(bytes, max_bytes, kind)
}

fn require_bounded(bytes: Vec<u8>, max_bytes: usize, kind: InputKind) -> Result<Vec<u8>, CliError> {
    if bytes.len() > max_bytes {
        return Err(kind.oversized_error(bytes.len(), max_bytes));
    }
    Ok(bytes)
}

/// Reads at most `max_bytes + 1` bytes of `path`, leaving the oversize decision to the caller.
pub(crate) fn read_file_capped(path: &Path, max_bytes: usize) -> Result<Vec<u8>, CliError> {
    read_file_reader_capped(open_file(path)?, path, max_bytes)
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
pub(crate) fn read_stdin_capped(max_bytes: usize, kind: InputKind) -> Result<Vec<u8>, CliError> {
    let stdin = io::stdin();
    require_redirected_stdin(kind, stdin.is_terminal())?;
    read_capped(stdin.lock(), max_bytes).map_err(|source| input_read_error(kind, source))
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
    fn error_handling_reads_retain_file_or_stdin_and_causes() {
        let path = Path::new("inputs/targets.txt");
        let error = read_file_reader_capped(FailingReader, path, 16).unwrap_err();
        assert!(error.message.contains(&path.display().to_string()));
        assert_eq!(error.classification.kind, Kind::Io);
        assert_eq!(error.causes, ["injected read failure"]);

        let error = read_bounded(FailingReader, 16, InputKind::Manifest).unwrap_err();
        assert!(error.message.contains("stdin"));
        assert_eq!(error.causes, ["injected read failure"]);
    }

    #[test]
    fn error_handling_file_bounds_and_missing_files_retain_paths_and_codes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("frame.bin");
        let error = read_bounded_file(&path, 1, InputKind::Frame).unwrap_err();
        assert_eq!(error.classification.kind, Kind::Io);
        assert!(error.message.contains(&path.display().to_string()));
        assert!(!error.causes.is_empty());

        std::fs::write(&path, b"a").unwrap();
        assert_eq!(read_bounded_file(&path, 1, InputKind::Frame).unwrap(), b"a");
        std::fs::write(&path, b"ab").unwrap();
        assert_eq!(
            read_bounded_file(&path, 2, InputKind::Frame).unwrap(),
            b"ab"
        );
        let error = read_bounded_file(&path, 1, InputKind::Frame).unwrap_err();
        assert_eq!(error.classification.code, "policy.decode_resource_limit");
        assert_eq!(error.classification.kind, Kind::Policy);
        assert!(error.message.contains(&path.display().to_string()));

        std::fs::write(&path, b"").unwrap();
        let error = read_bounded_file(&path, 1, InputKind::Frame).unwrap_err();
        assert_eq!(error.classification.code, "cli.input_source");
        assert!(error.message.contains(&path.display().to_string()));
        assert!(
            read_bounded_file_allow_empty(&path, 1, InputKind::Frame)
                .unwrap()
                .is_empty()
        );
    }
}
