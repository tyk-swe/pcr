// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use serde::Serialize;

use packetcraftr_core::error::{Classification, Classified, Kind};

pub const SCHEMA_V7: &str = "packetcraftr.output/v7";

pub use crate::commands::Command;

impl Command {
    pub fn require_format<F: FormatSubset>(self, format: Format) -> Result<F, Error> {
        match F::try_from(format) {
            Ok(narrowed) if self.formats().contains(&format) => Ok(narrowed),
            _ => Err(Error::UnsupportedFormat {
                command: self,
                format,
            }),
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
    Csv,
    Tsv,
    Hex,
    Raw,
    Pcap,
    PcapNg,
}

impl Format {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Csv => "csv",
            Self::Tsv => "tsv",
            Self::Json => "json",
            Self::Ndjson => "ndjson",
            Self::Hex => "hex",
            Self::Raw => "raw",
            Self::Pcap => "pcap",
            Self::PcapNg => "pcapng",
        }
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

pub trait FormatSubset: Copy + Into<Format> + TryFrom<Format, Error = Format> {
    const FORMATS: &'static [Format];
}

macro_rules! format_subset {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $($variant:ident),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant,)+
        }

        impl FormatSubset for $name {
            const FORMATS: &'static [Format] = &[$(Format::$variant),+];
        }

        impl $name {
            pub const fn as_format(self) -> Format {
                match self {
                    $(Self::$variant => Format::$variant,)+
                }
            }
        }

        impl From<$name> for Format {
            fn from(value: $name) -> Self {
                value.as_format()
            }
        }

        impl TryFrom<Format> for $name {
            type Error = Format;

            fn try_from(format: Format) -> Result<Self, Format> {
                match format {
                    $(Format::$variant => Ok(Self::$variant),)+
                    _ => Err(format),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.as_format().fmt(formatter)
            }
        }
    };
}

format_subset! {
    pub enum AggregateFormat {
        Text,
        Json,
    }
}

format_subset! {
    pub enum ToolFormat {
        Text,
        Json,
        Ndjson,
    }
}

format_subset! {
    pub enum BuildFormat {
        Text,
        Json,
        Ndjson,
        Hex,
        Raw,
        Pcap,
        PcapNg,
    }
}

format_subset! {
    pub enum CaptureFormat {
        Text,
        Json,
        Ndjson,
        Hex,
        Pcap,
        PcapNg,
    }
}

format_subset! {
    pub enum DissectFormat {
        Text,
        Json,
        Ndjson,
        Csv,
        Tsv,
        Hex,
        Raw,
    }
}

format_subset! {
    pub enum SendFormat {
        Text,
        Json,
        Hex,
        Raw,
        Pcap,
        PcapNg,
    }
}

format_subset! {
    pub enum ExchangeFormat {
        Text,
        Json,
        Ndjson,
        Pcap,
        PcapNg,
    }
}

format_subset! {
    pub enum ReadFormat {
        Text,
        Json,
        Ndjson,
        Csv,
        Tsv,
        Hex,
        Pcap,
        PcapNg,
    }
}

format_subset! {
    pub enum FollowFormat {
        Text,
        Json,
        Ndjson,
        Hex,
        Raw,
    }
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
