// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use serde::Serialize;

use packetcraftr_core::error::{Classification, Classified, Kind};

/// Current output contract identifier.
pub const SCHEMA: &str = packetcraftr_core::security::OUTPUT_SCHEMA;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Csv,
    Ndjson,
    Hex,
    Raw,
    Pcap,
    #[value(name = "pcapng")]
    PcapNg,
}

impl Format {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Csv => "csv",
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

pub(crate) const TEXT_JSON: &[Format] = &[Format::Text, Format::Json];
pub(crate) const TEXT_JSON_NDJSON: &[Format] = &[Format::Text, Format::Json, Format::Ndjson];

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
                packetcraftr_core::error::Code::CliOutputFormat,
                Kind::Usage,
                Some("choose one of the formats listed for this command"),
            ),
            Self::TimestampOutOfRange => Classification::new(
                packetcraftr_core::error::Code::PacketTimestampRange,
                Kind::Packet,
                Some("use a capture whose timestamp fits signed 64-bit Unix seconds"),
            ),
            Self::InvalidSourceFrame => Classification::new(
                packetcraftr_core::error::Code::InternalSourceFrame,
                Kind::Internal,
                Some("use the one-based source position assigned while reading or capturing"),
            ),
            Self::IncoherentFuzzEvents(_) => Classification::new(
                packetcraftr_core::error::Code::InternalFuzzEventCoherence,
                Kind::Internal,
                Some("collect cases from exactly one complete campaign in publication order"),
            ),
            Self::Unpublished { .. } => Classification::new(
                packetcraftr_core::error::Code::InternalError,
                Kind::Internal,
                None,
            ),
        }
    }
}

/// One published output shape: the Rust types that serialize to a schema
/// envelope definition for one command, the stream events they emit, and one
/// checked-in example validating against that definition. The output-schema
/// checker fails on any row whose definition, types, events, or example no
/// longer agree with the schema, the sources, and the examples.
pub struct PublishedType {
    pub definition: &'static str,
    pub command: &'static str,
    pub rust_types: &'static [&'static str],
    pub events: &'static [&'static str],
    pub example: &'static str,
}
