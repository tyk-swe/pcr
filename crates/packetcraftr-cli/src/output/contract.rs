// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use packetcraftr_core::error::{Classification, Classified, Kind};

use crate::command_catalog::command_catalog;

/// Current output contract identifier.
pub const OUTPUT_SCHEMA: &str = "packetcraftr.output/v23";
/// Releases 0.3.0 to 0.5.0-beta.2 and later unreleased builds each emitted this
/// identifier with a different schema, so no single schema can validate it.
pub const AMBIGUOUS_OUTPUT_SCHEMA: &str = "packetcraftr.output/v1";

pub(crate) fn payload_schema(command: &str) -> String {
    format!("packetcraftr.output.{command}/v1")
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct DiagnosticProjection {
    #[serde(default)]
    pub(crate) code: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AggregateEnvelope<T> {
    schema: String,
    pub(crate) command: String,
    mode: String,
    status: String,
    #[serde(default)]
    pub(crate) payload_schema: Option<String>,
    #[serde(default)]
    pub(crate) diagnostics: Vec<DiagnosticProjection>,
    pub(crate) result: T,
}

impl<T> AggregateEnvelope<T> {
    pub(crate) fn diagnostic_codes(&self) -> Vec<String> {
        self.diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AggregateInputError {
    #[error("invalid aggregate JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "{AMBIGUOUS_OUTPUT_SCHEMA} is ambiguous across releases, so regenerate the input with this release, which emits {OUTPUT_SCHEMA}"
    )]
    AmbiguousSchema,
    #[error("input must be successful aggregate {OUTPUT_SCHEMA} JSON from an allowed command")]
    InvalidEnvelope,
}

pub(crate) fn aggregate_input<T: DeserializeOwned>(
    bytes: &[u8],
    allowed_commands: &[&str],
) -> Result<AggregateEnvelope<T>, AggregateInputError> {
    let envelope: AggregateEnvelope<T> = serde_json::from_slice(bytes)?;
    if envelope.schema == AMBIGUOUS_OUTPUT_SCHEMA {
        return Err(AggregateInputError::AmbiguousSchema);
    }
    let payload_matches =
        envelope.payload_schema.as_deref() == Some(payload_schema(&envelope.command).as_str());
    if envelope.schema != OUTPUT_SCHEMA
        || envelope.status != "success"
        || envelope.mode != "aggregate"
        || !allowed_commands.contains(&envelope.command.as_str())
        || !payload_matches
    {
        return Err(AggregateInputError::InvalidEnvelope);
    }
    Ok(envelope)
}

macro_rules! published_commands {
    (@variant $name:literal, $variant:expr) => { $variant };
    (
        $(
            $(#[$attribute:meta])*
            $variant:ident($arguments:ty) $(= $name:literal [$($format:ident),+])?
                => ($group:literal, $canonical:literal),
        )*
    ) => {
        /// CLI command identifier frozen into the output schema.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
        pub enum Command {
            $( $( #[serde(rename = $name)] $variant, )? )*
        }

        impl Command {
            pub const ALL: &'static [Self] = &[
                $( $( published_commands!(@variant $name, Self::$variant), )? )*
            ];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $( Self::$variant => $name, )? )*
                }
            }

            pub const fn formats(self) -> &'static [Format] {
                match self {
                    $( $( Self::$variant => &[$(Format::$format),+], )? )*
                }
            }
        }

    };
}

command_catalog!(published_commands);

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

pub(crate) const OUTPUT_FORMATS_HELP: &str = r"Output formats:
  text    Human-readable summaries and diagnostics.
  json    One aggregate JSON document.
  csv     Flat statistics tables with a header (excluding overview/fragments).
  ndjson  One JSON record per streamed event.
  hex     Exact frame bytes as hexadecimal text.
  raw     Exact frame bytes without text framing.
  pcap    Classic PCAP capture bytes.
  pcapng  PCAPNG capture bytes.

Output availability is command-specific. Machine formats never contain terminal colour codes.";

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
                crate::code::CliOutputFormat,
                Kind::Usage,
                Some("choose one of the formats listed for this command"),
            ),
            Self::TimestampOutOfRange => Classification::new(
                crate::code::PacketTimestampRange,
                Kind::Packet,
                Some("use a capture whose timestamp fits signed 64-bit Unix seconds"),
            ),
            Self::InvalidSourceFrame => Classification::new(
                crate::code::InternalSourceFrame,
                Kind::Internal,
                Some("use the one-based source position assigned while reading or capturing"),
            ),
            Self::IncoherentFuzzEvents(_) => Classification::new(
                crate::code::InternalFuzzEventCoherence,
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
