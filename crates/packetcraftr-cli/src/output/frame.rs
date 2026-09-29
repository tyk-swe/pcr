// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::num::NonZeroU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::{Serialize, Serializer};

use packetcraftr_core::frame::{self as library_frame, Frame};
use packetcraftr_core::{decode::DecodedPacket, layout};

use super::contract::Error;
use super::diagnostic::Diagnostic;
use super::hex::CompactHex;

const NANOS_PER_SECOND: u32 = 1_000_000_000;

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
    fn from_pre_epoch_duration(before: Duration) -> Result<Self, Error> {
        let whole = i128::from(before.as_secs());
        let (seconds, nanoseconds) = match before.subsec_nanos() {
            0 => (-whole, 0),
            nanos => (-whole - 1, NANOS_PER_SECOND - nanos),
        };
        Ok(Self {
            unix_seconds: i64::try_from(seconds).map_err(|_| Error::TimestampOutOfRange)?,
            nanoseconds,
        })
    }
}

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

published_enum! {
    pub enum Direction from library_frame::Direction {
        Inbound => "inbound",
        Outbound => "outbound",
        Unknown => "unknown",
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

impl From<layout::ByteRange> for ByteRange {
    fn from(value: layout::ByteRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FieldLayout {
    pub name: &'static str,
    pub range: ByteRange,
}

impl From<layout::FieldLayout> for FieldLayout {
    fn from(value: layout::FieldLayout) -> Self {
        Self {
            name: value.name,
            range: value.range.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LayerLayout {
    pub index: usize,
    pub protocol: &'static str,
    pub range: ByteRange,
    pub fields: Vec<FieldLayout>,
}

impl From<layout::LayerLayout> for LayerLayout {
    fn from(value: layout::LayerLayout) -> Self {
        Self {
            index: value.index,
            protocol: value.protocol.as_str(),
            range: value.range.into(),
            fields: value.fields.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Layout {
    pub layers: Vec<LayerLayout>,
}

impl From<layout::PacketLayout> for Layout {
    fn from(value: layout::PacketLayout) -> Self {
        Self {
            layers: value.layers.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<&layout::PacketLayout> for Layout {
    fn from(value: &layout::PacketLayout) -> Self {
        value.clone().into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Wire {
    #[serde(rename = "bytes_hex", serialize_with = "hex")]
    bytes: Bytes,
    pub length: u64,
}

impl From<Bytes> for Wire {
    fn from(bytes: Bytes) -> Self {
        Self {
            length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            bytes,
        }
    }
}

impl Wire {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn bytes_hex(&self) -> impl std::fmt::Display + '_ {
        CompactHex(&self.bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Captured {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
    pub captured_length: u32,
    pub original_length: u32,
    pub link_type: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    #[serde(rename = "bytes_hex", serialize_with = "hex")]
    bytes: Bytes,
}

impl TryFrom<Frame> for Captured {
    type Error = Error;

    fn try_from(frame: Frame) -> Result<Self, Error> {
        Ok(Self {
            timestamp: frame.timestamp.map(Timestamp::try_from).transpose()?,
            captured_length: frame.captured_length(),
            original_length: frame.original_length(),
            link_type: frame.link_type.0,
            interface: frame.interface,
            direction: frame.direction.map(Into::into),
            bytes: frame.bytes().clone(),
        })
    }
}

impl Captured {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn bytes_hex(&self) -> impl std::fmt::Display + '_ {
        CompactHex(&self.bytes)
    }
}

fn hex<S: Serializer>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error> {
    CompactHex(bytes).serialize(serializer)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Stack {
    pub packet: packetcraftr_core::document::Packet,
    pub layout: Layout,
    pub diagnostics: Vec<Diagnostic>,
}

impl From<&DecodedPacket> for Stack {
    fn from(decoded: &DecodedPacket) -> Self {
        Self {
            packet: packetcraftr_core::document::Packet::from_packet(&decoded.packet),
            layout: (&decoded.layout).into(),
            diagnostics: decoded.diagnostics.iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Decoded {
    pub frame: Captured,
    pub packet: packetcraftr_core::document::Packet,
    pub layout: Layout,
    pub diagnostics: Vec<Diagnostic>,
}

impl TryFrom<DecodedPacket> for Decoded {
    type Error = Error;

    fn try_from(decoded: DecodedPacket) -> Result<Self, Error> {
        let DecodedPacket {
            packet,
            frame,
            layout,
            diagnostics,
        } = decoded;
        Ok(Self {
            frame: frame.try_into()?,
            packet: packetcraftr_core::document::Packet::from_packet(&packet),
            layout: layout.into(),
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
        })
    }
}

#[cfg(test)]
mod tests {

    use packetcraftr_core::frame::{Lengths, LinkType};

    use super::*;

    const HALF_RANGE_SECONDS: u64 = 1 << 63;

    #[test]
    fn wire_serializes_hex_bytes_before_length() {
        let wire = Wire::from(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]));

        assert_eq!(
            serde_json::to_string(&wire).unwrap(),
            r#"{"bytes_hex":"deadbeef","length":4}"#
        );
    }

    #[test]
    fn captured_serializes_every_present_field_in_published_order() {
        let mut frame = Frame::try_with_lengths(
            UNIX_EPOCH + Duration::new(1, 500),
            LinkType::ETHERNET,
            Lengths {
                captured: 2,
                original: 60,
            },
            vec![0xab, 0xcd],
        )
        .unwrap();
        frame.interface = Some(3);
        frame.direction = Some(library_frame::Direction::Inbound);

        let captured = Captured::try_from(frame).unwrap();

        assert_eq!(
            serde_json::to_string(&captured).unwrap(),
            concat!(
                r#"{"timestamp":{"unix_seconds":1,"nanoseconds":500},"#,
                r#""captured_length":2,"original_length":60,"link_type":1,"#,
                r#""interface":3,"direction":"inbound","bytes_hex":"abcd"}"#
            )
        );
    }

    #[test]
    fn captured_omits_absent_timestamp_interface_and_direction() {
        let frame = Frame::without_timestamp(LinkType::ETHERNET, vec![0x45]).unwrap();

        let captured = Captured::try_from(frame).unwrap();

        assert_eq!(
            serde_json::to_string(&captured).unwrap(),
            r#"{"captured_length":1,"original_length":1,"link_type":1,"bytes_hex":"45"}"#
        );
    }

    #[test]
    fn pre_epoch_offsets_use_floor_seconds() {
        for ((seconds, nanoseconds), expected) in [
            ((0, 0), (0, 0)),
            ((3, 0), (-3, 0)),
            ((0, 500_000_000), (-1, 500_000_000)),
            ((0, 1), (-1, 999_999_999)),
            ((2, 250_000_000), (-3, 750_000_000)),
            ((i64::MAX as u64, 0), (-i64::MAX, 0)),
        ] {
            let timestamp =
                Timestamp::from_pre_epoch_duration(Duration::new(seconds, nanoseconds)).unwrap();
            assert_eq!(
                (timestamp.unix_seconds, timestamp.nanoseconds),
                expected,
                "{seconds}s {nanoseconds}ns before the epoch"
            );
        }
    }

    #[test]
    fn pre_epoch_offsets_reach_the_minimum_signed_second_and_no_further() {
        let minimum = Timestamp::from_pre_epoch_duration(Duration::new(HALF_RANGE_SECONDS, 0))
            .expect("exactly i64::MIN seconds before the epoch is representable");
        assert_eq!((minimum.unix_seconds, minimum.nanoseconds), (i64::MIN, 0));

        let fractional_minimum =
            Timestamp::from_pre_epoch_duration(Duration::new(i64::MAX as u64, 1))
                .expect("a fraction past i64::MAX seconds floors to i64::MIN");
        assert_eq!(
            (
                fractional_minimum.unix_seconds,
                fractional_minimum.nanoseconds
            ),
            (i64::MIN, 999_999_999)
        );

        for (seconds, nanoseconds) in [
            (HALF_RANGE_SECONDS, 1),
            (HALF_RANGE_SECONDS + 1, 0),
            (u64::MAX, 0),
            (u64::MAX, 999_999_999),
        ] {
            assert_eq!(
                Timestamp::from_pre_epoch_duration(Duration::new(seconds, nanoseconds)),
                Err(Error::TimestampOutOfRange),
                "{seconds}s {nanoseconds}ns before the epoch"
            );
        }
    }

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
