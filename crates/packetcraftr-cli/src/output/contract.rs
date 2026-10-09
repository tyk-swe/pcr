// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use serde::Serialize;

use packetcraftr_core::error::{Classification, Classified, Kind};

pub const SCHEMA_V6: &str = "packetcraftr.output/v6";
pub const SCHEMA_V7: &str = "packetcraftr.output/v7";
pub const SCHEMA_V8: &str = "packetcraftr.output/v8";
pub const SCHEMA_V9: &str = "packetcraftr.output/v9";
pub const SCHEMA_V10: &str = "packetcraftr.output/v10";

pub use crate::commands::Command;

impl Command {
    pub fn require_format(self, format: Format) -> Result<Format, Error> {
        if self.formats().contains(&format) {
            Ok(format)
        } else {
            Err(Error::UnsupportedFormat {
                command: self,
                format,
            })
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    Text,
    Json,
    Ndjson,
    Hex,
    Raw,
    Pcap,
    PcapNg,
}

impl Format {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Ndjson => "ndjson",
            Self::Hex => "hex",
            Self::Raw => "raw",
            Self::Pcap => "pcap",
            Self::PcapNg => "pcapng",
        }
    }

    pub(crate) fn unreachable(self) -> ! {
        unreachable!("dispatch already selected a supported format: {self}")
    }
}

impl fmt::Display for Format {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Aggregate,
    Stream,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(
        "{command} does not support {format} output; choose {}",
        supported_formats(command)
    )]
    UnsupportedFormat { command: Command, format: Format },
    #[error("capture timestamp is outside the signed output range")]
    TimestampOutOfRange,
    #[error("source frame must be a non-zero unsigned 64-bit position")]
    InvalidSourceFrame,
    #[error("fuzz events are incoherent: {0}")]
    IncoherentFuzzEvents(#[from] packetcraftr_core::fuzz::IncoherentReport),
    #[error("{value} has no representation in the published output contract")]
    Unpublished { value: &'static str },
}

fn supported_formats(command: &Command) -> String {
    command
        .formats()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::UnsupportedFormat { .. } => Classification::new(
                "cli.output_format",
                Kind::Usage,
                Some("choose one of the formats listed for this command"),
            ),
            Self::TimestampOutOfRange => Classification::new(
                "packet.timestamp_range",
                Kind::Packet,
                Some("use a capture whose timestamp fits signed 64-bit Unix seconds"),
            ),
            Self::InvalidSourceFrame => Classification::new(
                "internal.source_frame",
                Kind::Internal,
                Some("use the one-based source position assigned while reading or capturing"),
            ),
            Self::IncoherentFuzzEvents(_) => Classification::new(
                "internal.fuzz_event_coherence",
                Kind::Internal,
                Some("collect cases from exactly one complete campaign in publication order"),
            ),
            Self::Unpublished { .. } => Classification::new("internal.error", Kind::Internal, None),
        }
    }
}
