// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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

/// The one `--compression` argument.
///
/// Compression applies to capture bytes only, so a command reads it through
/// [`for_output`](Self::for_output), which rejects it for any other stdout
/// format, or through [`for_file`](Self::for_file) for a saved capture file.
#[derive(Clone, Copy, Debug, clap::Args)]
pub(crate) struct CompressionArgs {
    /// Compress binary capture output or a saved capture file.
    #[arg(long, value_enum, default_value_t = Compression::None)]
    compression: Compression,
}

impl CompressionArgs {
    pub(crate) fn for_output(self, format: Format) -> Result<Compression, CliError> {
        if !matches!(self.compression, Compression::None)
            && !matches!(format, Format::Pcap | Format::PcapNg)
        {
            return Err(CliError::new(
                Kind::Usage,
                "--compression requires PCAP or PCAPNG output",
            ));
        }
        Ok(self.compression)
    }

    pub(crate) const fn for_file(self) -> Compression {
        self.compression
    }
}
