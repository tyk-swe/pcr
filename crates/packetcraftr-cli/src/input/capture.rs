// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::path::Path;

use packetcraftr_core as core;
use packetcraftr_core::capture_file::{Reader, ReaderLimits};

use super::bounded::{InputKind, open_file, require_redirected_stdin};
use super::fingerprint::{self, Fingerprint};
use crate::command_options::OfflineCaptureLimits;
use crate::errors::CliError;

fn capture_source(
    invocation: &crate::invocation::Invocation,
    path: &Path,
) -> Result<Box<dyn Read>, CliError> {
    invocation.check()?;
    if path == Path::new("-") {
        let stdin = io::stdin();
        require_redirected_stdin(InputKind::Capture, stdin.is_terminal())?;
        Ok(Box::new(stdin.lock()))
    } else {
        Ok(Box::new(open_file(path)?))
    }
}

pub(crate) fn open_capture(
    invocation: &crate::invocation::Invocation,
    path: &Path,
    limits: OfflineCaptureLimits,
) -> Result<Reader<Box<dyn Read>>, CliError> {
    capture_reader(invocation, capture_source(invocation, path)?, limits)
}

pub(crate) fn open_capture_hashed(
    invocation: &crate::invocation::Invocation,
    path: &Path,
    limits: OfflineCaptureLimits,
) -> Result<(Reader<Box<dyn Read>>, Fingerprint), CliError> {
    let (source, fingerprint) = fingerprint::Hashed::new(capture_source(invocation, path)?);
    Ok((capture_reader(invocation, source, limits)?, fingerprint))
}

pub(crate) fn open_capture_file(
    invocation: &crate::invocation::Invocation,
    path: &Path,
    limits: OfflineCaptureLimits,
) -> Result<Reader<Box<dyn Read>>, CliError> {
    capture_reader(invocation, open_file(path)?, limits)
}

pub(crate) fn snapshot_capture<R: Read>(
    invocation: &crate::invocation::Invocation,
    input: &mut Reader<R>,
    capture_limits: OfflineCaptureLimits,
    limits: core::capture_file::Limits,
) -> Result<Reader<File>, CliError> {
    use core::capture_file;
    invocation.check()?;
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
    invocation.check()?;
    bounded_reader(invocation, snapshot, capture_limits)
}

fn capture_reader<R: Read + 'static>(
    invocation: &crate::invocation::Invocation,
    source: R,
    limits: OfflineCaptureLimits,
) -> Result<Reader<Box<dyn Read>>, CliError> {
    invocation.check()?;
    let bounds = limits.reader_bounds();
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
    let reader = bounded_reader(invocation, source, limits)?;
    invocation.check()?;
    Ok(reader)
}

fn bounded_reader<R: Read>(
    invocation: &crate::invocation::Invocation,
    source: R,
    limits: OfflineCaptureLimits,
) -> Result<Reader<R>, CliError> {
    let bounds = limits.reader_bounds();
    Reader::with_limits(
        source,
        ReaderLimits {
            max_size: bounds.max_frame_bytes,
            max_interfaces_per_section: bounds.max_interfaces,
            ..ReaderLimits::default()
        },
    )
    .map(|reader| invocation.reader(reader.with_cancellation(invocation.cancellation.clone())))
    .map_err(CliError::classified)
}
