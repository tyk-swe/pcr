// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::path::Path;

use packetcraftr_core as core;
use packetcraftr_core::capture_file::{Reader, ReaderLimits};

use super::bounded::{InputKind, open_file, require_redirected_stdin};
use super::fingerprint::{self, Fingerprint};
use crate::command_options::CaptureReaderBoundsArgs;
use crate::errors::CliError;

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
    bounded_reader(snapshot, bounds)
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
    let reader = bounded_reader(source, bounds)?;
    crate::cancellation::check()?;
    Ok(reader)
}

fn bounded_reader<R: Read>(
    source: R,
    bounds: CaptureReaderBoundsArgs,
) -> Result<Reader<R>, CliError> {
    Reader::with_limits(
        source,
        ReaderLimits {
            max_size: bounds.max_frame_bytes,
            max_interfaces_per_section: bounds.max_interfaces,
            ..ReaderLimits::default()
        },
    )
    .map(|reader| {
        crate::invocation::reader(reader.with_cancellation(crate::cancellation::signal().clone()))
    })
    .map_err(CliError::classified)
}
