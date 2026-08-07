// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;

use thiserror::Error;

use super::model::Format;
use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::frame::FrameError;

/// An error while reading or writing an offline capture.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Frame(#[from] FrameError),
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
    #[error(
        "pcapng block of {block_length} bytes crosses the section boundary with {remaining} bytes remaining"
    )]
    BlockCrossesSectionBoundary { block_length: u32, remaining: u64 },
    #[error("pcapng section ended with {remaining} declared bytes remaining")]
    SectionEndedEarly { remaining: u64 },
    #[error("new pcapng section begins with {remaining} declared bytes remaining")]
    SectionHeaderBeforeBoundary { remaining: u64 },
    #[error("pcapng section has {remaining} bytes remaining, fewer than a complete block header")]
    SectionRemainderTooSmall { remaining: u64 },
    #[error("timestamp cannot be represented in {format}")]
    TimestampOutOfRange { format: Format },
    #[error("timestamp fraction {fraction} is invalid for a denominator of {denominator}")]
    InvalidTimestampFraction { fraction: u32, denominator: u32 },
    #[error("link type {link_type} cannot be represented in a capture interface header")]
    LinkTypeOutOfRange { link_type: u32 },
    #[error("interface {interface} is not defined (the section has {available} interfaces)")]
    UndefinedInterface { interface: u32, available: usize },
    #[error("pcapng section exceeds the configured interface limit of {limit}")]
    InterfaceLimit { limit: usize },
    #[error("pcapng stream exceeds the configured retained-interface limit of {limit}")]
    TotalInterfaceLimit { limit: usize },
    #[error("pcapng stream exceeded {limit} metadata blocks before the next packet")]
    MetadataBlockLimit { limit: usize },
    #[error("pcapng stream exceeded {limit} metadata bytes before the next packet")]
    MetadataByteLimit { limit: usize },
    #[error("frame link type {actual} does not match interface {interface} link type {expected}")]
    InterfaceLinkTypeMismatch {
        interface: u32,
        expected: u32,
        actual: u32,
    },
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
            Self::InvalidTimestampResolution { .. } => Classification::new(
                "cli.capture_option",
                Kind::Cli,
                Some("use a supported finite capture timestamp or replay timing option"),
            ),
            Self::WrongWriterFormat { .. } => Classification::new(
                "cli.capture_option",
                Kind::Cli,
                Some("call the writer method that matches the writer's configured format"),
            ),
            Self::SizeLimitExceeded { .. }
            | Self::InterfaceLimit { .. }
            | Self::TotalInterfaceLimit { .. }
            | Self::MetadataBlockLimit { .. }
            | Self::MetadataByteLimit { .. }
            | Self::FrameLimitExceeded { .. }
            | Self::StreamByteLimitExceeded { .. } => Classification::new(
                "policy.capture_stream_limit",
                Kind::Policy,
                Some(
                    "reduce the capture stream or deliberately raise its finite frame/byte budget",
                ),
            ),
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
