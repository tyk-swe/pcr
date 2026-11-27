// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, BufWriter, Read, Seek, Write};

use packetcraftr_core::capture_file as capture;
use packetcraftr_core::capture_file::Reader;
use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Kind;

use super::selection::Selection;
use crate::capture_output::finish_compressed_output;
use crate::command_options::{Compression, OfflineCaptureLimits};
use crate::errors::CliError;
use crate::invocation::Control;
use crate::output::contract::Format;

const PUBLICATION_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
pub(super) enum CaptureOutput {
    Verbatim(capture::Format),
    Normalized(capture::Format),
}

impl CaptureOutput {
    pub(super) fn resolve(normalize: bool, format: Format) -> Result<Option<Self>, CliError> {
        let format = match format {
            Format::Pcap => capture::Format::Pcap,
            Format::PcapNg => capture::Format::PcapNg,
            _ if normalize => {
                return Err(CliError::from_classification(
                    Classification::new(
                        crate::code::CliCaptureNormalizeFormat,
                        Kind::Usage,
                        Some("use --normalize with --output pcapng or --output pcap"),
                    ),
                    "--normalize requires PCAP or PCAPNG output",
                    Vec::new(),
                ));
            }
            _ => return Ok(None),
        };
        Ok(Some(if normalize {
            Self::Normalized(format)
        } else {
            Self::Verbatim(format)
        }))
    }

    pub(super) fn validate_input(self, input: capture::Format) -> Result<(), CliError> {
        match self {
            Self::Verbatim(output) => validate_rewrite_format(input, output),
            Self::Normalized(_) => Ok(()),
        }
    }

    pub(super) fn write_stdout(
        self,
        reader: &mut Reader<impl Read>,
        limits: OfflineCaptureLimits,
        selection: Selection<'_>,
        compression: Compression,
        mut destination: impl Write,
        control: &Control,
    ) -> Result<(), CliError> {
        if matches!(self, Self::Verbatim(_)) && selection.is_unrestricted() {
            let mut output = compression.writer(destination)?;
            let result = self.write(reader, limits, selection, &mut output);
            return finish_compressed_output(result, output);
        }

        let io_error = |error| CliError::classified(capture::Error::from(error));
        let mut staged = tempfile::tempfile().map_err(io_error)?;
        let mut output =
            compression.writer(BufWriter::with_capacity(PUBLICATION_CHUNK_BYTES, &mut staged))?;
        let result = self.write(reader, limits, selection, &mut output);
        finish_compressed_output(result, output)?;
        staged.rewind().map_err(io_error)?;
        publish_staged(&mut staged, &mut destination, control)
    }

    fn write(
        self,
        reader: &mut Reader<impl Read>,
        limits: OfflineCaptureLimits,
        selection: Selection<'_>,
        destination: &mut impl Write,
    ) -> Result<(), CliError> {
        match self {
            Self::Verbatim(_) => {
                rewrite_capture(reader, limits.stream_limits(), selection, destination)
            }
            Self::Normalized(format) => {
                super::normalize::run(reader, limits, selection, format, destination).map(drop)
            }
        }
    }
}

fn publish_staged(
    staged: &mut impl Read,
    destination: &mut impl Write,
    control: &Control,
) -> Result<(), CliError> {
    let io_error = |error| CliError::classified(capture::Error::from(error));
    let mut buffer = [0; PUBLICATION_CHUNK_BYTES];
    loop {
        control.check()?;
        let bytes = match staged.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result.map_err(io_error)?,
        };
        control.check()?;
        if bytes == 0 {
            return destination.flush().map_err(io_error);
        }
        destination.write_all(&buffer[..bytes]).map_err(io_error)?;
    }
}

/// Checked before stdout is wrapped, so a rejected conversion writes no compressed container.
fn validate_rewrite_format(
    input: capture::Format,
    output: capture::Format,
) -> Result<(), CliError> {
    if output != input {
        return Err(CliError::from_classification(
            Classification::new(
                crate::code::CliCaptureRewriteFormat,
                Kind::Usage,
                Some("select the capture output format matching the input capture"),
            ),
            format!(
                "capture rewriting cannot convert {input} input to {output} without normalization"
            ),
            Vec::new(),
        ));
    }
    Ok(())
}

fn rewrite_capture(
    reader: &mut Reader<impl Read>,
    limits: capture::Limits,
    selection: Selection<'_>,
    destination: &mut impl Write,
) -> Result<(), CliError> {
    if selection.is_unrestricted() {
        return capture::rewrite(reader, destination, limits)
            .map(|_| ())
            .map_err(CliError::classified);
    }
    capture::select(reader, destination, limits, |number, frame| {
        selection
            .matches(number, frame)
            .map_err(CliError::into_boundary_error)
    })
    .map(|_| ())
    .map_err(CliError::classified)
}

#[cfg(test)]
mod tests {
    use super::{Control, PUBLICATION_CHUNK_BYTES, publish_staged};
    use packetcraftr_core::budget::Cancellation;
    use std::io::{self, Write};

    struct CancelOnWrite {
        cancellation: Cancellation,
        bytes: usize,
    }

    impl Write for CancelOnWrite {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes += bytes.len();
            self.cancellation.cancel();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("cancelled publication called flush");
        }
    }

    #[test]
    fn staged_capture_stops_publication_after_cancellation() {
        let cancellation = Cancellation::default();
        let control = Control::new(None, cancellation.clone());
        let mut writer = CancelOnWrite {
            cancellation,
            bytes: 0,
        };
        let staged = vec![0; PUBLICATION_CHUNK_BYTES + 1];

        let error = publish_staged(&mut staged.as_slice(), &mut writer, &control).unwrap_err();

        assert_eq!(
            error.classification.code,
            packetcraftr_core::error::Code::IoCancelled
        );
        assert_eq!(writer.bytes, PUBLICATION_CHUNK_BYTES);
    }
}
