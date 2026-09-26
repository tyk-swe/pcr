// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use packetcraftr_core::capture_file::compression::{self, Output};

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub(crate) enum Compression {
    #[default]
    None,
    Gzip,
    Zstd,
}
impl Compression {
    pub(crate) fn validate(self, format: crate::output::contract::Format) -> Result<(), CliError> {
        if !matches!(self, Self::None)
            && !matches!(
                format,
                crate::output::contract::Format::Pcap | crate::output::contract::Format::PcapNg
            )
        {
            return Err(CliError::new(
                packetcraftr_core::error::Kind::Usage,
                "--compression requires PCAP or PCAPNG output",
            ));
        }
        Ok(())
    }
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
