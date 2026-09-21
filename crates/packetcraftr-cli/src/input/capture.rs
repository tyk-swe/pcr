// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded capture sources, decompression, fingerprints, and seekable snapshots.

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::path::Path;

use packetcraftr_core as core;
use packetcraftr_core::analysis::pcap::{Reader, ReaderOptions};
use packetcraftr_core::error::{Classification, Kind};

use super::{Fingerprint, InputKind, fingerprint, open_file, require_redirected_stdin};
use crate::command_options::{CaptureReaderBoundsArgs, OfflineCaptureLimitsArgs};
use crate::errors::CliError;

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
    limits: core::analysis::pcap::Limits,
) -> Result<Reader<File>, CliError> {
    use core::analysis::pcap;
    crate::cancellation::check()?;
    let snapshot = tempfile::tempfile()
        .map_err(pcap::Error::from)
        .map_err(CliError::classified)?;
    let (snapshot, _) = pcap::rewrite(
        input,
        io::BufWriter::with_capacity(64 * 1024, snapshot),
        limits,
    )
    .map_err(CliError::classified)?;
    let mut snapshot = snapshot
        .into_inner()
        .map_err(|error| CliError::classified(pcap::Error::from(error.into_error())))?;
    std::io::Seek::rewind(&mut snapshot)
        .map_err(pcap::Error::from)
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
        core::analysis::pcap::compression::Input::new(
            source,
            core::analysis::pcap::compression::Limits {
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
    use super::*;

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
}
