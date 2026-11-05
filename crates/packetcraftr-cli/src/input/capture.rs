// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::path::Path;

use packetcraftr_core as core;
use packetcraftr_core::capture_file::{Reader, ReaderLimits};

use super::bounded::{InputKind, open_file, redirected_stdin};
use super::fingerprint::{self, Fingerprint};
use super::source::{Source, interrupted_or};
use crate::command_options::OfflineCaptureLimits;
use crate::errors::CliError;

fn capture_source(
    invocation: &crate::invocation::Invocation,
    path: &Path,
) -> Result<Source, CliError> {
    invocation.check()?;
    if path == Path::new("-") {
        redirected_stdin(invocation, InputKind::Capture)
    } else {
        open_file(invocation, path)
    }
}

pub(crate) fn open_capture(
    invocation: &crate::invocation::Invocation,
    path: &Path,
    limits: OfflineCaptureLimits,
) -> Result<Reader<Box<dyn Read>>, CliError> {
    let source = capture_source(invocation, path)?;
    invocation
        .output
        .observe_input(source.is_regular_file() && !io::stdout().is_terminal());
    capture_reader(invocation, source, limits)
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
    capture_reader(invocation, open_file(invocation, path)?, limits)
}

pub(crate) fn snapshot_capture<R: Read>(
    invocation: &crate::invocation::Invocation,
    input: &mut Reader<R>,
    capture_limits: OfflineCaptureLimits,
    limits: core::capture_file::Limits,
) -> Result<Reader<io::BufReader<File>>, CliError> {
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
    .map_err(|error| interrupted_or(invocation, CliError::classified(error)))?;
    let mut snapshot = snapshot
        .into_inner()
        .map_err(|error| CliError::classified(capture_file::Error::from(error.into_error())))?;
    std::io::Seek::rewind(&mut snapshot)
        .map_err(capture_file::Error::from)
        .map_err(CliError::classified)?;
    invocation.check()?;
    bounded_reader(
        invocation,
        io::BufReader::with_capacity(64 * 1024, snapshot),
        capture_limits,
    )
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
        .map_err(|error| interrupted_or(invocation, CliError::classified(error)))?,
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
    .map_err(|error| interrupted_or(invocation, CliError::classified(error)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_options::{CaptureReaderBoundsArgs, OfflineCaptureLimitsArgs};
    use packetcraftr_core::capture_file::{Format, Writer};
    use packetcraftr_core::frame::{Frame, LinkType};
    use std::io::Cursor;
    use std::time::{Duration, UNIX_EPOCH};

    fn limits() -> OfflineCaptureLimits {
        OfflineCaptureLimitsArgs {
            max_frames: 500,
            max_bytes: 1_000_000,
            reader: CaptureReaderBoundsArgs {
                max_encoded_bytes: 1_000_000,
                max_decoded_bytes: 1_000_000,
                max_frame_bytes: 100_000,
                max_interfaces: 16,
            },
        }
        .limits()
        .unwrap()
    }

    fn capture(format: Format) -> Vec<u8> {
        let mut writer = Writer::new(Vec::new(), format, LinkType::ETHERNET).unwrap();
        for index in 0..128 {
            let frame = Frame::new(
                Some(UNIX_EPOCH + Duration::from_secs(index)),
                LinkType::ETHERNET,
                vec![u8::try_from(index).unwrap(); 64],
            )
            .unwrap();
            writer.write_frame(&frame).unwrap();
        }
        writer.into_inner()
    }

    #[test]
    fn staged_readback_preserves_capture_controls() {
        for format in [Format::Pcap, Format::PcapNg] {
            let bytes = capture(format);
            let cancellation = packetcraftr_core::budget::Cancellation::default();
            let invocation = super::super::source::test_invocation(None, cancellation.clone());
            let mut source =
                Reader::with_limits(Cursor::new(bytes.clone()), Default::default()).unwrap();
            let mut snapshot =
                snapshot_capture(&invocation, &mut source, limits(), limits().stream_limits())
                    .unwrap();
            let frames = snapshot.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
            assert_eq!(frames.len(), 128);
            assert_eq!(frames[127].bytes().as_ref(), &[127; 64]);
            snapshot.rewind().unwrap();
            assert_eq!(snapshot.next_frame().unwrap().as_ref(), frames.first());
            cancellation.cancel();
            assert!(matches!(
                snapshot.next_frame(),
                Err(packetcraftr_core::capture_file::Error::Cancelled(_))
            ));
            assert!(snapshot.rewind().is_err());

            let invocation = super::super::source::test_invocation(None, Default::default());
            let mut source =
                Reader::with_limits(Cursor::new(bytes.clone()), Default::default()).unwrap();
            assert!(
                snapshot_capture(
                    &invocation,
                    &mut source,
                    limits(),
                    packetcraftr_core::capture_file::Limits {
                        max_frames: 1,
                        max_bytes: 1_000_000
                    }
                )
                .is_err()
            );
            let mut truncated = bytes;
            truncated.truncate(truncated.len() - 1);
            let mut source =
                Reader::with_limits(Cursor::new(truncated), Default::default()).unwrap();
            assert!(
                snapshot_capture(&invocation, &mut source, limits(), limits().stream_limits())
                    .is_err()
            );
        }
    }
}
