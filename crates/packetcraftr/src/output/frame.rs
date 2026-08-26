// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared wire, captured, and decoded frame representations.

use std::num::NonZeroU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::Serialize;

use packetcraftr_core::frame::Frame;
use packetcraftr_core::{decode::DecodedPacket, layout::PacketLayout};

use super::contract::Error;
use super::envelope::Diagnostic;
use super::hex::CompactHex;

const MAX_SIGNED_SECONDS: u64 = i64::MAX as u64;

/// Validated one-based position in an input capture stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SourceFrame(NonZeroU64);

impl SourceFrame {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for SourceFrame {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(Error::InvalidSourceFrame)
    }
}

impl std::fmt::Display for SourceFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Canonical signed Unix timestamp used by output records, including pre-epoch captures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Timestamp {
    pub unix_seconds: i64,
    pub nanoseconds: u32,
}

impl TryFrom<SystemTime> for Timestamp {
    type Error = Error;

    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Ok(Self {
                unix_seconds: i64::try_from(duration.as_secs())
                    .map_err(|_| Error::TimestampOutOfRange)?,
                nanoseconds: duration.subsec_nanos(),
            }),
            Err(source) => Self::from_pre_epoch_duration(source.duration()),
        }
    }
}

impl Timestamp {
    pub(crate) fn from_pre_epoch_duration(duration: Duration) -> Result<Self, Error> {
        if duration.subsec_nanos() == 0 {
            let unix_seconds = if duration.as_secs() == MAX_SIGNED_SECONDS + 1 {
                i64::MIN
            } else {
                i64::try_from(duration.as_secs())
                    .ok()
                    .and_then(i64::checked_neg)
                    .ok_or(Error::TimestampOutOfRange)?
            };
            Ok(Self {
                unix_seconds,
                nanoseconds: 0,
            })
        } else {
            let seconds = duration.as_secs();
            if seconds > MAX_SIGNED_SECONDS {
                return Err(Error::TimestampOutOfRange);
            }
            // A fractional instant before the epoch is represented with
            // floor seconds. `i64::MAX` seconds plus a fraction therefore
            // maps to `(i64::MIN, positive nanos)`, which is still inside the
            // v1 signed-seconds range.
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "`seconds` is below `MAX_SIGNED_SECONDS` here, the equal case having \
                          been taken above, so `signed_seconds + 1` and its negation both stay \
                          inside `i64`"
            )]
            let unix_seconds = if seconds == MAX_SIGNED_SECONDS {
                i64::MIN
            } else {
                #[expect(
                    clippy::cast_possible_wrap,
                    reason = "the guard above returns TimestampOutOfRange for seconds greater \
                              than i64::MAX, so this conversion stays positive"
                )]
                let signed_seconds = seconds as i64;
                -(signed_seconds + 1)
            };
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "`subsec_nanos` is always below 1_000_000_000, so the subtraction cannot \
                          underflow"
            )]
            let nanoseconds = 1_000_000_000 - duration.subsec_nanos();
            Ok(Self {
                unix_seconds,
                nanoseconds,
            })
        }
    }
}

/// Exact complete-frame bytes used by raw/hex/capture renderers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wire {
    bytes: Bytes,
    pub length: u64,
}

impl Wire {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        Self {
            length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            bytes,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Formats the exact bytes as compact lowercase hexadecimal without
    /// retaining a second owned representation.
    pub fn bytes_hex(&self) -> impl std::fmt::Display + '_ {
        CompactHex(&self.bytes)
    }
}

impl Serialize for Wire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Output<'a> {
            bytes_hex: CompactHex<'a>,
            length: u64,
        }

        Output {
            bytes_hex: CompactHex(&self.bytes),
            length: self.length,
        }
        .serialize(serializer)
    }
}

pub use packetcraftr_core::frame::Direction;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Captured {
    bytes: Bytes,
    /// Capture time, omitted when the source record does not provide one.
    pub timestamp: Option<Timestamp>,
    pub captured_length: u32,
    pub original_length: u32,
    pub link_type: u32,
    pub interface: Option<u32>,
    pub direction: Option<Direction>,
}

impl Captured {
    pub fn try_from_frame(frame: Frame) -> Result<Self, Error> {
        Ok(Self {
            timestamp: frame.timestamp.map(Timestamp::try_from).transpose()?,
            captured_length: frame.captured_length(),
            original_length: frame.original_length(),
            link_type: frame.link_type.0,
            interface: frame.interface,
            direction: frame.direction,
            bytes: frame.bytes().clone(),
        })
    }

    pub(crate) fn try_from_frames(frames: Vec<Frame>) -> Result<Vec<Self>, Error> {
        frames.into_iter().map(Self::try_from_frame).collect()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Formats the exact bytes as compact lowercase hexadecimal without
    /// retaining a second owned representation.
    pub fn bytes_hex(&self) -> impl std::fmt::Display + '_ {
        CompactHex(&self.bytes)
    }
}

impl Serialize for Captured {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Output<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            timestamp: Option<Timestamp>,
            captured_length: u32,
            original_length: u32,
            link_type: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            interface: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            direction: Option<Direction>,
            bytes_hex: CompactHex<'a>,
        }

        Output {
            timestamp: self.timestamp,
            captured_length: self.captured_length,
            original_length: self.original_length,
            link_type: self.link_type,
            interface: self.interface,
            direction: self.direction,
            bytes_hex: CompactHex(&self.bytes),
        }
        .serialize(serializer)
    }
}

/// A dissected frame's layer stack, excluding the raw frame to avoid serializing
/// it twice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Stack {
    pub packet: packetcraftr_core::document::Packet,
    pub layout: PacketLayout,
    pub diagnostics: Vec<Diagnostic>,
}

impl Stack {
    pub fn from_decoded(decoded: &DecodedPacket) -> Self {
        Self {
            packet: packetcraftr_core::document::Packet::from_packet(&decoded.packet),
            layout: decoded.layout.clone(),
            diagnostics: decoded
                .diagnostics
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
        }
    }
}

/// A decoded frame retained by exchange-like tools.
#[derive(Clone, Debug, Serialize)]
pub struct Decoded {
    pub frame: Captured,
    pub packet: packetcraftr_core::document::Packet,
    pub layout: PacketLayout,
    pub diagnostics: Vec<Diagnostic>,
}

impl Decoded {
    pub fn try_from_decoded(decoded: DecodedPacket) -> Result<Self, Error> {
        let DecodedPacket {
            packet,
            original: _,
            frame,
            layout,
            diagnostics,
        } = decoded;
        Ok(Self {
            frame: Captured::try_from_frame(frame)?,
            packet: packetcraftr_core::document::Packet::from_packet(&packet),
            layout,
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
        })
    }
}
