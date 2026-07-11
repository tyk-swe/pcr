/// Default maximum size of an offline packet or a PCAPNG block (16 MiB).
pub const DEFAULT_SIZE_LIMIT: usize = 16 * 1024 * 1024;
/// Default maximum number of interface descriptions retained per PCAPNG section.
pub const DEFAULT_INTERFACE_LIMIT: usize = 4_096;
/// Default maximum metadata blocks consumed before one packet is returned.
pub const DEFAULT_METADATA_BLOCK_LIMIT: usize = 4_096;
/// Default maximum frames accepted by one streaming capture writer or copy.
pub const DEFAULT_STREAM_FRAMES: u64 = 10_000;
/// Default maximum captured payload bytes accepted by one streaming writer or copy.
pub const DEFAULT_STREAM_BYTES: u64 = 256 * 1024 * 1024;

/// Aggregate frame and captured-byte ceilings for a streaming capture operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_frames: u64,
    pub max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_STREAM_FRAMES,
            max_bytes: DEFAULT_STREAM_BYTES,
        }
    }
}

/// Capture container format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// The classic libpcap file format.
    Pcap,
    /// The extensible pcapng file format.
    PcapNg,
}

impl fmt::Display for Format {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pcap => "pcap",
            Self::PcapNg => "pcapng",
        })
    }
}

/// Byte order used by a capture file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    #[default]
    Little,
    Big,
}

/// Timestamp tick resolution declared by classic PCAP or one PCAPNG interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampResolution {
    Decimal(u8),
    Binary(u8),
}

/// Metadata associated with one capture interface.
///
/// The index in [`Reader::interfaces`] is the global interface ID used
/// by [`Frame::interface`]. Multiple PCAPNG sections are normalized to
/// one monotonically increasing namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub link_type: LinkType,
    pub snap_len: u32,
    pub timestamp_resolution: TimestampResolution,
    pub timestamp_offset: i64,
}

/// Result of a bounded streaming capture copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscodeReport {
    pub source_format: Format,
    pub target_format: Format,
    pub endianness: Endianness,
    pub frames: u64,
    pub captured_bytes: u64,
    pub interfaces: usize,
}

/// An error while reading or writing an offline capture.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("capture I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("capture input is empty")]
    EmptyInput,
    #[error("unrecognized capture magic {magic:02x?}")]
    UnrecognizedFormat { magic: [u8; 4] },
    #[error("truncated {context}: expected {expected} bytes, found {actual}")]
    Truncated {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("unsupported {format} version {major}.{minor}")]
    UnsupportedVersion {
        format: Format,
        major: u16,
        minor: u16,
    },
    #[error("invalid {format} data: {reason}")]
    InvalidData {
        format: Format,
        reason: &'static str,
    },
    #[error("{kind} declares {declared} bytes, exceeding the configured limit of {limit}")]
    SizeLimitExceeded {
        kind: &'static str,
        declared: u64,
        limit: usize,
    },
    #[error("pcapng block has invalid length {length}")]
    InvalidBlockLength { length: u32 },
    #[error("pcapng block length footer {trailing} does not match header {leading}")]
    BlockLengthMismatch { leading: u32, trailing: u32 },
    #[error("captured frame contains {actual} bytes, exceeding the u32 capture-record limit")]
    CapturedLengthTooLarge { actual: usize },
    #[error("frame captured length says {declared} bytes but contains {actual}")]
    CapturedLengthMismatch { declared: u32, actual: usize },
    #[error("frame original length {original} is smaller than captured length {captured}")]
    OriginalLengthTooSmall { captured: u32, original: u32 },
    #[error("timestamp cannot be represented in {format}")]
    TimestampOutOfRange { format: Format },
    #[error("timestamp fraction {fraction} is invalid for a denominator of {denominator}")]
    InvalidTimestampFraction { fraction: u32, denominator: u32 },
    #[error("link type {link_type} cannot be represented in pcapng")]
    LinkTypeOutOfRange { link_type: u32 },
    #[error("interface {interface} is not defined (the section has {available} interfaces)")]
    UndefinedInterface { interface: u32, available: usize },
    #[error("pcapng section exceeds the configured interface limit of {limit}")]
    InterfaceLimit { limit: usize },
    #[error("pcapng stream exceeded {limit} metadata blocks before the next packet")]
    MetadataBlockLimit { limit: usize },
    #[error("frame link type {actual} does not match interface {interface} link type {expected}")]
    InterfaceLinkTypeMismatch {
        interface: u32,
        expected: u32,
        actual: u32,
    },
    #[error("no pcapng interface is registered for link type {link_type}")]
    NoInterfaceForLinkType { link_type: u32 },
    #[error("more than one pcapng interface uses link type {link_type}; select one explicitly")]
    AmbiguousInterface { link_type: u32 },
    #[error("{field} metadata cannot be represented in {format}")]
    MetadataNotRepresentable { format: Format, field: &'static str },
    #[error("this operation requires {expected}, but the writer is configured for {actual}")]
    WrongWriterFormat { expected: Format, actual: Format },
    #[error("capture stream frame count {actual} exceeds the configured limit of {limit}")]
    FrameLimitExceeded { actual: u64, limit: u64 },
    #[error("capture stream payload bytes {actual} exceed the configured limit of {limit}")]
    StreamByteLimitExceeded { actual: u64, limit: u64 },
    #[error("capture timestamp resolution {base}^{exponent} cannot be represented")]
    InvalidTimestampResolution { base: u8, exponent: u8 },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Io(_) => Classification::new(
                "io.capture_file",
                Kind::Io,
                Some(
                    "inspect the capture input/output stream and retry from a known record boundary",
                ),
            ),
            Self::InvalidTimestampResolution { .. } => {
                Classification::new(
                    "cli.capture_option",
                    Kind::Cli,
                    Some("use a supported finite capture timestamp or replay timing option"),
                )
            }
            Self::FrameLimitExceeded { .. } | Self::StreamByteLimitExceeded { .. } => {
                Classification::new(
                    "policy.capture_stream_limit",
                    Kind::Policy,
                    Some(
                        "reduce the capture stream or deliberately raise its finite frame/byte budget",
                    ),
                )
            }
            _ => Classification::new(
                "packet.capture_file",
                Kind::Packet,
                Some("repair the malformed or unrepresentable capture record before processing it"),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Io(source) => vec![source.to_string()],
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimestampPrecision {
    Microseconds,
    Nanoseconds,
}

type InterfaceDescription = Interface;
