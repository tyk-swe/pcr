// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output-version, command, and format contracts.

use std::fmt;

use serde::{Deserialize, Serialize};

use packetcraftr_core::error::{Classification, Classified, Kind};

/// Version identifier emitted by every structured CLI record.
pub const SCHEMA_V1: &str = "packetcraftr.output/v1";

/// CLI command identifier frozen into the v1 output schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    Build,
    Dissect,
    Plan,
    Send,
    Exchange,
    Capture,
    Expert,
    Follow,
    Read,
    Replay,
    Scan,
    Stats,
    Traceroute,
    Dns,
    Fuzz,
    Interfaces,
    Routes,
    Protocols,
}

impl Command {
    /// Complete v1 command vocabulary in canonical serialized order.
    pub const ALL: &'static [Self] = &[
        Self::Build,
        Self::Dissect,
        Self::Protocols,
        Self::Plan,
        Self::Send,
        Self::Exchange,
        Self::Capture,
        Self::Read,
        Self::Replay,
        Self::Scan,
        Self::Stats,
        Self::Expert,
        Self::Follow,
        Self::Traceroute,
        Self::Dns,
        Self::Fuzz,
        Self::Interfaces,
        Self::Routes,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Dissect => "dissect",
            Self::Protocols => "protocols",
            Self::Plan => "plan",
            Self::Send => "send",
            Self::Exchange => "exchange",
            Self::Capture => "capture",
            Self::Expert => "expert",
            Self::Follow => "follow",
            Self::Read => "read",
            Self::Replay => "replay",
            Self::Scan => "scan",
            Self::Stats => "stats",
            Self::Traceroute => "traceroute",
            Self::Dns => "dns",
            Self::Fuzz => "fuzz",
            Self::Interfaces => "interfaces",
            Self::Routes => "routes",
        }
    }

    /// Formats deliberately supported by this command contract.
    pub const fn formats(self) -> &'static [Format] {
        match self {
            Self::Build | Self::Dissect => BUILD_FORMATS,
            Self::Protocols | Self::Plan | Self::Interfaces | Self::Routes | Self::Stats => {
                AGGREGATE_FORMATS
            }
            Self::Send => SEND_FORMATS,
            Self::Exchange => EXCHANGE_FORMATS,
            Self::Capture | Self::Read => CAPTURE_FORMATS,
            Self::Replay => REPLAY_FORMATS,
            Self::Follow => FOLLOW_FORMATS,
            Self::Scan | Self::Traceroute | Self::Dns | Self::Fuzz | Self::Expert => TOOL_FORMATS,
        }
    }

    /// Rejects unsupported combinations before a command performs I/O.
    pub fn require_format(self, format: Format) -> Result<(), Error> {
        if self.formats().contains(&format) {
            Ok(())
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

/// User-selectable output formats across supported commands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    #[default]
    Text,
    Json,
    Ndjson,
    Hex,
    Raw,
    Pcap,
    #[serde(rename = "pcapng")]
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

const BUILD_FORMATS: &[Format] = &[Format::Text, Format::Json, Format::Hex, Format::Raw];
const AGGREGATE_FORMATS: &[Format] = &[Format::Text, Format::Json];
const SEND_FORMATS: &[Format] = &[
    Format::Text,
    Format::Json,
    Format::Hex,
    Format::Raw,
    Format::Pcap,
    Format::PcapNg,
];
const EXCHANGE_FORMATS: &[Format] = &[
    Format::Text,
    Format::Json,
    Format::Ndjson,
    Format::Pcap,
    Format::PcapNg,
];
const CAPTURE_FORMATS: &[Format] = &[
    Format::Text,
    Format::Ndjson,
    Format::Hex,
    Format::Pcap,
    Format::PcapNg,
];
const REPLAY_FORMATS: &[Format] = &[
    Format::Text,
    Format::Json,
    Format::Ndjson,
    Format::Pcap,
    Format::PcapNg,
];
const TOOL_FORMATS: &[Format] = &[Format::Text, Format::Json, Format::Ndjson];
const FOLLOW_FORMATS: &[Format] = &[
    Format::Text,
    Format::Json,
    Format::Ndjson,
    Format::Hex,
    Format::Raw,
];

/// Failure produced while enforcing the shared output contract.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    UnsupportedFormat { command: Command, format: Format },
    TimestampOutOfRange,
    InvalidSourceFrame,
    IncoherentFuzzEvents { message: String },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat { command, format } => {
                write!(
                    formatter,
                    "{command} does not support {format} output; choose "
                )?;
                for (index, supported) in command.formats().iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{supported}")?;
                }
                Ok(())
            }
            Self::TimestampOutOfRange => {
                formatter.write_str("capture timestamp is outside the signed v1 output range")
            }
            Self::InvalidSourceFrame => {
                formatter.write_str("source frame must be a non-zero unsigned 64-bit position")
            }
            Self::IncoherentFuzzEvents { message } => {
                write!(formatter, "fuzz events are incoherent: {message}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::UnsupportedFormat { .. } => Classification::new(
                "cli.output_format",
                Kind::Cli,
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
