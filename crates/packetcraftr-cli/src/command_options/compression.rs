// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `--compression`, defined once for every command that writes captures.

use std::fmt;
use std::marker::PhantomData;

use packetcraftr_core::capture_file::compression::{self, Output};
use packetcraftr_core::error::Kind;

use crate::errors::CliError;
use crate::output::contract::Format;

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub(crate) enum Compression {
    #[default]
    None,
    Gzip,
    Zstd,
}

impl Compression {
    pub(crate) fn format(self) -> compression::Format {
        match self {
            Self::None => compression::Format::None,
            Self::Gzip => compression::Format::Gzip,
            Self::Zstd => compression::Format::Zstd,
        }
    }

    pub(crate) fn writer<W: std::io::Write>(self, writer: W) -> Result<Output<W>, CliError> {
        Output::new(writer, self.format()).map_err(CliError::classified)
    }
}

/// What a command's `--compression` compresses.
pub(crate) trait Destination:
    Clone + Copy + fmt::Debug + Default + Send + Sync + 'static
{
    const HELP: &'static str;
}

/// The one `--compression` argument.
///
/// Compression applies to capture bytes only, so a command reads it through
/// [`for_output`](Self::for_output), which rejects it for any other stdout
/// format, or through [`for_file`](Self::for_file) for a saved capture file.
#[derive(Clone, Copy, Debug, clap::Args)]
pub(crate) struct CompressionArgs<D: Destination> {
    #[arg(long, value_enum, default_value_t = Compression::None, help = D::HELP)]
    compression: Compression,
    #[arg(skip)]
    destination: PhantomData<D>,
}

impl<D: Destination> CompressionArgs<D> {
    /// The compression of capture bytes written to stdout in `format`.
    ///
    /// # Errors
    ///
    /// A usage error when compression is requested for a format other than
    /// PCAP or PCAPNG.
    pub(crate) fn for_output(self, format: impl Into<Format>) -> Result<Compression, CliError> {
        if !matches!(self.compression, Compression::None)
            && !matches!(format.into(), Format::Pcap | Format::PcapNg)
        {
            return Err(CliError::new(
                Kind::Usage,
                "--compression requires PCAP or PCAPNG output",
            ));
        }
        Ok(self.compression)
    }

    /// The compression of a saved capture file, whatever stdout reports.
    pub(crate) const fn for_file(self) -> Compression {
        self.compression
    }
}

/// Capture bytes written to stdout.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CaptureStdout;

impl Destination for CaptureStdout {
    const HELP: &'static str =
        "Compress binary capture output; independent of the input's detected format";
}

/// A saved PCAPNG file.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SavedPcapNg;

impl Destination for SavedPcapNg {
    const HELP: &'static str = "Compression of the saved PCAPNG file";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdout_compression_requires_capture_output() {
        let compressed = CompressionArgs::<CaptureStdout> {
            compression: Compression::Gzip,
            destination: PhantomData,
        };
        for format in [Format::Pcap, Format::PcapNg] {
            assert!(matches!(
                compressed.for_output(format),
                Ok(Compression::Gzip)
            ));
        }
        for format in [Format::Text, Format::Json, Format::Ndjson, Format::Hex] {
            let error = compressed.for_output(format).unwrap_err();
            assert_eq!(error.exit_code(), 2);
        }
        let plain = CompressionArgs::<CaptureStdout> {
            compression: Compression::None,
            destination: PhantomData,
        };
        assert!(plain.for_output(Format::Text).is_ok());
        assert!(matches!(compressed.for_file(), Compression::Gzip));
    }
}
