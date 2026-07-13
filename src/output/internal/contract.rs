/// Version identifier emitted by every structured CLI record.
pub const OUTPUT_SCHEMA_V2: &str = "packetcraftr.output/v2";

/// CLI command identifier frozen into the v2 output schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandName {
    Build,
    Dissect,
    Plan,
    Send,
    Exchange,
    Capture,
    Read,
    Replay,
    Scan,
    Traceroute,
    Dns,
    Fuzz,
    Interfaces,
    Routes,
    Doctor,
}

impl CommandName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Dissect => "dissect",
            Self::Plan => "plan",
            Self::Send => "send",
            Self::Exchange => "exchange",
            Self::Capture => "capture",
            Self::Read => "read",
            Self::Replay => "replay",
            Self::Scan => "scan",
            Self::Traceroute => "traceroute",
            Self::Dns => "dns",
            Self::Fuzz => "fuzz",
            Self::Interfaces => "interfaces",
            Self::Routes => "routes",
            Self::Doctor => "doctor",
        }
    }

    /// Formats deliberately supported by this command contract.
    pub const fn formats(self) -> &'static [OutputFormat] {
        match self {
            Self::Build | Self::Dissect => BUILD_FORMATS,
            Self::Plan | Self::Interfaces | Self::Routes | Self::Doctor => AGGREGATE_FORMATS,
            Self::Send => SEND_FORMATS,
            Self::Exchange => EXCHANGE_FORMATS,
            Self::Capture => CAPTURE_FORMATS,
            Self::Read => READ_FORMATS,
            Self::Replay => REPLAY_FORMATS,
            Self::Scan | Self::Traceroute | Self::Dns | Self::Fuzz => TOOL_FORMATS,
        }
    }

    /// Rejects unsupported combinations before a command performs I/O.
    pub fn require_format(self, format: OutputFormat) -> Result<(), OutputContractError> {
        if self.formats().contains(&format) {
            Ok(())
        } else {
            Err(OutputContractError::UnsupportedFormat {
                command: self,
                format,
            })
        }
    }
}

impl fmt::Display for CommandName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// User-selectable output formats across supported commands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Ndjson,
    Hex,
    Raw,
    Pcap,
    Pcapng,
}

impl OutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Ndjson => "ndjson",
            Self::Hex => "hex",
            Self::Raw => "raw",
            Self::Pcap => "pcap",
            Self::Pcapng => "pcapng",
        }
    }

    /// Structured output mode, if this is a machine-envelope format.
    pub const fn mode(self) -> Option<OutputMode> {
        match self {
            Self::Json => Some(OutputMode::Aggregate),
            Self::Ndjson => Some(OutputMode::Stream),
            Self::Text | Self::Hex | Self::Raw | Self::Pcap | Self::Pcapng => None,
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Whether one structured value is an aggregate JSON result or an NDJSON record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    Aggregate,
    Stream,
}

/// One row in the public command/format capability matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandOutputContract {
    pub command: CommandName,
    pub formats: &'static [OutputFormat],
}

const BUILD_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Hex,
    OutputFormat::Raw,
];
const AGGREGATE_FORMATS: &[OutputFormat] = &[OutputFormat::Text, OutputFormat::Json];
const SEND_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Hex,
    OutputFormat::Raw,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const EXCHANGE_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Ndjson,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const CAPTURE_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Ndjson,
    OutputFormat::Hex,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const READ_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Ndjson,
    OutputFormat::Hex,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const REPLAY_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Ndjson,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const TOOL_FORMATS: &[OutputFormat] =
    &[OutputFormat::Text, OutputFormat::Json, OutputFormat::Ndjson];

/// Complete v2 command/format matrix. Extending a command requires changing this table.
pub const COMMAND_OUTPUT_CONTRACTS: &[CommandOutputContract] = &[
    CommandOutputContract {
        command: CommandName::Build,
        formats: BUILD_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Dissect,
        formats: BUILD_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Plan,
        formats: AGGREGATE_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Send,
        formats: SEND_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Exchange,
        formats: EXCHANGE_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Capture,
        formats: CAPTURE_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Read,
        formats: READ_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Replay,
        formats: REPLAY_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Scan,
        formats: TOOL_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Traceroute,
        formats: TOOL_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Dns,
        formats: TOOL_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Fuzz,
        formats: TOOL_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Interfaces,
        formats: AGGREGATE_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Routes,
        formats: AGGREGATE_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Doctor,
        formats: AGGREGATE_FORMATS,
    },
];

/// Failure produced while enforcing the shared output contract.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutputContractError {
    UnsupportedFormat {
        command: CommandName,
        format: OutputFormat,
    },
    InvalidFrame {
        message: String,
    },
    TimestampOutOfRange,
    SequenceOverflow,
}

impl fmt::Display for OutputContractError {
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
            Self::InvalidFrame { message } => {
                write!(formatter, "invalid captured frame for output: {message}")
            }
            Self::TimestampOutOfRange => {
                formatter.write_str("capture timestamp is outside the signed v2 output range")
            }
            Self::SequenceOverflow => {
                formatter.write_str("NDJSON sequence exceeded the v2 unsigned 64-bit range")
            }
        }
    }
}

impl std::error::Error for OutputContractError {}

impl Classified for OutputContractError {
    fn classification(&self) -> Classification {
        match self {
            Self::UnsupportedFormat { .. } => Classification::new(
                "cli.output_format",
                Kind::Cli,
                Some("choose one of the formats listed for this command"),
            ),
            Self::InvalidFrame { .. } => Classification::new(
                "packet.capture_record",
                Kind::Packet,
                Some("repair the capture record lengths before rendering it"),
            ),
            Self::TimestampOutOfRange => Classification::new(
                "packet.timestamp_range",
                Kind::Packet,
                Some("use a capture whose timestamp fits signed 64-bit Unix seconds"),
            ),
            Self::SequenceOverflow => Classification::new(
                "internal.output_sequence",
                Kind::Internal,
                Some("split the stream before the unsigned 64-bit sequence limit"),
            ),
        }
    }
}
