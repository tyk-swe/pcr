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
const NANOS_PER_SECOND: u32 = 1_000_000_000;

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
    fn from_pre_epoch_duration(duration: Duration) -> Result<Self, Error> {
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
            let nanoseconds = NANOS_PER_SECOND - duration.subsec_nanos();
            Ok(Self {
                unix_seconds,
                nanoseconds,
            })
        }
    }
}

/// The inverse of the pre-epoch floor-seconds encoding above: `(-3,
/// 750_000_000)` is 0.75 s after -3 s, which is -2.25 s in conventional signed
/// decimal notation. Every renderer prints a timestamp through this, so the two
/// halves of the rule cannot drift apart.
impl std::fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.unix_seconds >= 0 || self.nanoseconds == 0 {
            return write!(formatter, "{}.{:09}", self.unix_seconds, self.nanoseconds);
        }
        let whole_seconds = self.unix_seconds.saturating_add(1).saturating_neg();
        let fractional = NANOS_PER_SECOND.saturating_sub(self.nanoseconds);
        write!(formatter, "-{whole_seconds}.{fractional:09}")
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

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;

    /// The floor-seconds pair and its rendering are inverses: `(-3,
    /// 750_000_000)` is 0.75 s after -3 s, so it reads as -2.25 s.
    #[test]
    fn timestamp_display_uses_conventional_signed_decimal_notation() {
        for ((unix_seconds, nanoseconds), expected) in [
            ((3, 250_000_000), "3.250000000"),
            ((0, 0), "0.000000000"),
            ((-3, 750_000_000), "-2.250000000"),
            ((-1, 999_999_999), "-0.000000001"),
            ((-3, 0), "-3.000000000"),
        ] {
            let timestamp = Timestamp {
                unix_seconds,
                nanoseconds,
            };
            assert_eq!(timestamp.to_string(), expected);
        }
    }

    /// Encoding an instant and rendering it recovers the offset it was built
    /// from, on both sides of the epoch. Windows SystemTime uses 100 ns ticks.
    #[test]
    fn every_encoded_instant_renders_its_own_offset_from_the_epoch() {
        for (offset, before_epoch, expected) in [
            (Duration::ZERO, false, "0.000000000"),
            (Duration::from_nanos(100), false, "0.000000100"),
            (Duration::new(3, 250_000_000), false, "3.250000000"),
            (Duration::from_nanos(100), true, "-0.000000100"),
            (Duration::new(2, 250_000_000), true, "-2.250000000"),
            (Duration::new(3, 0), true, "-3.000000000"),
        ] {
            let instant = if before_epoch {
                UNIX_EPOCH - offset
            } else {
                UNIX_EPOCH + offset
            };
            let timestamp = Timestamp::try_from(instant).expect("in-range instant encodes");
            assert_eq!(timestamp.to_string(), expected);
        }
    }
}
