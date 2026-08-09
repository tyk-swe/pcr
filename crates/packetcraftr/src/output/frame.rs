// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared wire, captured, and decoded frame representations.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::Serialize;

use packetcraftr_packet::frame::Frame;
use packetcraftr_packet::{
    decode::Result as DecodedPacket, document::Packet as PacketDocument,
    layout::Packet as PacketLayout,
};

use super::contract::Error;
use super::envelope::Diagnostic;
use super::hex::compact_hex;

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
            let unix_seconds = if duration.as_secs() == i64::MAX as u64 + 1 {
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
            if seconds > i64::MAX as u64 {
                return Err(Error::TimestampOutOfRange);
            }
            // A fractional instant before the epoch is represented with
            // floor seconds. `i64::MAX` seconds plus a fraction therefore
            // maps to `(i64::MIN, positive nanos)`, which is still inside the
            // v1 signed-seconds range.
            let unix_seconds = if seconds == i64::MAX as u64 {
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
            Ok(Self {
                unix_seconds,
                nanoseconds: 1_000_000_000 - duration.subsec_nanos(),
            })
        }
    }
}

/// Exact complete-frame bytes used by raw/hex/capture renderers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Wire {
    #[serde(skip)]
    bytes: Bytes,
    pub bytes_hex: String,
    pub length: u64,
}

impl Wire {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        Self {
            bytes_hex: compact_hex(&bytes),
            length: bytes.len() as u64,
            bytes,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Shared capture-frame representation for read, capture, exchange, and evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

impl From<packetcraftr_packet::frame::Direction> for Direction {
    fn from(value: packetcraftr_packet::frame::Direction) -> Self {
        match value {
            packetcraftr_packet::frame::Direction::Inbound => Self::Inbound,
            packetcraftr_packet::frame::Direction::Outbound => Self::Outbound,
            packetcraftr_packet::frame::Direction::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Captured {
    #[serde(skip)]
    bytes: Bytes,
    /// Capture time, omitted when the source record does not provide one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
    pub captured_length: u32,
    pub original_length: u32,
    pub link_type: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    pub bytes_hex: String,
}

impl Captured {
    pub fn try_from_frame(frame: Frame) -> Result<Self, Error> {
        Ok(Self {
            timestamp: frame.timestamp.map(Timestamp::try_from).transpose()?,
            captured_length: frame.captured_length(),
            original_length: frame.original_length(),
            link_type: frame.link_type.0,
            interface: frame.interface,
            direction: frame.direction.map(Into::into),
            bytes_hex: compact_hex(frame.bytes()),
            bytes: frame.bytes().clone(),
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A dissected frame's layer stack, excluding the raw frame to avoid serializing
/// it twice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Stack {
    pub packet: PacketDocument,
    pub layout: PacketLayout,
    pub diagnostics: Vec<Diagnostic>,
}

impl Stack {
    pub fn from_decoded(decoded: &DecodedPacket) -> Self {
        Self {
            packet: PacketDocument::from_packet(&decoded.packet),
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
    pub packet: PacketDocument,
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
            packet: PacketDocument::from_packet(&packet),
            layout,
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
        })
    }
}
