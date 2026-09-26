// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output-version, command, and format contracts.

use std::fmt;

use serde::Serialize;

use packetcraftr_core::error::{Classification, Classified, Kind};

/// Version identifier emitted by every structured CLI record.
pub const SCHEMA_V6: &str = "packetcraftr.output/v6";

/// CLI command identifier frozen into the output schema.
///
/// The variants, their serialized names, [`Command::ALL`], and
/// [`Command::formats`] come from the one command declaration in the CLI's
/// command module, so the published vocabulary and the parsed command line
/// cannot drift apart.
pub use crate::commands::Kind as Command;

impl Command {
    /// Rejects unsupported combinations before a command performs I/O,
    /// returning the format narrowed to the enum the command dispatches on so
    /// its matches are exhaustive without an `unreachable!` fallback.
    ///
    /// `F` is the command's narrow format type, inferred from the call site.
    /// Both the command's declared [`formats`](Self::formats) and `F`'s own
    /// subset are checked, so a mismatched `F` still rejects rather than
    /// silently admitting a format the command does not support.
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

/// User-selectable output formats across supported commands. Never a document
/// field: a format is chosen on the command line, so it has no default here.
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

/// Whether one structured value is an aggregate JSON result or an NDJSON record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Aggregate,
    Stream,
}

/// One command's narrow output-format enum: the subset of [`Format`] its
/// contract admits, which the command matches exhaustively.
pub trait FormatSubset: Copy + Into<Format> + TryFrom<Format, Error = Format> {
    /// The subset as shared [`Format`] values, in declared order.
    const FORMATS: &'static [Format];
}

/// Declares a narrow output-format enum covering one command's supported
/// subset of [`Format`]. Each variant maps to the [`Format`] of the same
/// name: `FORMATS` is the subset as `Format` values, [`From`] widens a narrow
/// value into `Format`, and [`TryFrom`] narrows a checked `Format`, returning
/// the rejected value on failure. Commands match their own enum exhaustively,
/// so a newly added [`Format`] variant becomes a compile error at every site
/// that must handle it rather than a runtime `unreachable!`.
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
            /// The shared [`Format`] this narrowed value denotes.
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
    /// Formats for commands that emit one aggregate document or text lines.
    pub enum AggregateFormat {
        Text,
        Json,
    }
}

format_subset! {
    /// Formats for commands that either stream records or emit one aggregate
    /// document or text lines.
    pub enum ToolFormat {
        Text,
        Json,
        Ndjson,
    }
}

format_subset! {
    /// Formats the `build` command emits.
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
    /// Formats the `capture` and `fragment` commands emit.
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
    /// Formats the `dissect` command emits.
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
    /// Formats the `send` command emits.
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
    /// Formats the `exchange` and `replay` commands emit.
    pub enum ExchangeFormat {
        Text,
        Json,
        Ndjson,
        Pcap,
        PcapNg,
    }
}

format_subset! {
    /// Formats the `read` command emits.
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
    /// Formats the `follow` command emits.
    pub enum FollowFormat {
        Text,
        Json,
        Ndjson,
        Hex,
        Raw,
    }
}

/// Failure produced while enforcing the shared output contract.
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
    #[error("fuzz events are incoherent: {message}")]
    IncoherentFuzzEvents { message: String },
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
            Self::IncoherentFuzzEvents { .. } => Classification::new(
                "internal.fuzz_event_coherence",
                Kind::Internal,
                Some("collect cases from exactly one complete campaign in publication order"),
            ),
        }
    }
}
