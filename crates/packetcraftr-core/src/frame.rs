// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-neutral captured frame bytes and metadata.

use std::time::SystemTime;

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::error::{Classification, Classified, Kind};

/// Default maximum size of a captured frame (16 MiB).
pub const DEFAULT_SIZE_LIMIT: usize = 16 * 1024 * 1024;

/// Capture-wide interface identifier normalized across PCAPNG sections.
pub type GlobalInterfaceId = u32;

/// Open numeric libpcap link-layer type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LinkType(pub u32);

impl LinkType {
    pub const NULL: Self = Self(0);
    pub const ETHERNET: Self = Self(1);
    /// BSD raw-IP DLT, distinct from the IANA-assigned raw LINKTYPE.
    pub const BSD_RAW: Self = Self(12);
    pub const RAW: Self = Self(101);
    pub const LOOP: Self = Self(108);
    pub const LINUX_SLL: Self = Self(113);
    pub const IPV4: Self = Self(228);
    pub const IPV6: Self = Self(229);
    pub const LINUX_SLL2: Self = Self(276);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

/// A frame construction or metadata invariant failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("captured frame contains {actual} bytes, exceeding the u32 capture-record limit")]
    CapturedLengthTooLarge { actual: usize },
    #[error("frame captured length says {declared} bytes but contains {actual}")]
    CapturedLengthMismatch { declared: u32, actual: usize },
    #[error("frame original length {original} is smaller than captured length {captured}")]
    OriginalLengthTooSmall { captured: u32, original: u32 },
    #[error("time bounds are reversed: the start is after the end")]
    ReversedTimeBounds { start: SystemTime, end: SystemTime },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::CapturedLengthTooLarge { .. }
            | Self::CapturedLengthMismatch { .. }
            | Self::OriginalLengthTooSmall { .. } => Classification::new(
                "packet.frame_metadata",
                Kind::Packet,
                Some("repair the capture record whose declared and actual frame lengths disagree"),
            ),
            Self::ReversedTimeBounds { .. } => Classification::new(
                "cli.reversed_time_bounds",
                Kind::Cli,
                Some("order the bounds so the earlier time comes first"),
            ),
        }
    }
}

/// Complete bytes and capture metadata, independent of successful dissection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Frame {
    /// Capture time, or [`None`] when the source record carries no timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<SystemTime>,
    captured_length: u32,
    original_length: u32,
    pub link_type: LinkType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<GlobalInterfaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    bytes: Bytes,
}

impl Frame {
    pub fn new(
        timestamp: SystemTime,
        link_type: LinkType,
        bytes: impl Into<Bytes>,
    ) -> Result<Self, Error> {
        Self::with_inferred_lengths(Some(timestamp), link_type, bytes)
    }

    pub fn try_with_lengths(
        timestamp: SystemTime,
        link_type: LinkType,
        captured_length: u32,
        original_length: u32,
        bytes: impl Into<Bytes>,
    ) -> Result<Self, Error> {
        Self::try_with_optional_timestamp(
            Some(timestamp),
            link_type,
            captured_length,
            original_length,
            bytes,
        )
    }

    /// Constructs a frame whose source record does not provide a timestamp.
    pub fn without_timestamp(link_type: LinkType, bytes: impl Into<Bytes>) -> Result<Self, Error> {
        Self::with_inferred_lengths(None, link_type, bytes)
    }

    fn with_inferred_lengths(
        timestamp: Option<SystemTime>,
        link_type: LinkType,
        bytes: impl Into<Bytes>,
    ) -> Result<Self, Error> {
        let bytes = bytes.into();
        let length = u32::try_from(bytes.len()).map_err(|_| Error::CapturedLengthTooLarge {
            actual: bytes.len(),
        })?;
        Self::try_with_optional_timestamp(timestamp, link_type, length, length, bytes)
    }

    /// Constructs a frame with explicit lengths and optional capture time.
    pub fn try_with_optional_timestamp(
        timestamp: Option<SystemTime>,
        link_type: LinkType,
        captured_length: u32,
        original_length: u32,
        bytes: impl Into<Bytes>,
    ) -> Result<Self, Error> {
        let bytes = bytes.into();
        if usize::try_from(captured_length) != Ok(bytes.len()) {
            return Err(Error::CapturedLengthMismatch {
                declared: captured_length,
                actual: bytes.len(),
            });
        }
        if original_length < captured_length {
            return Err(Error::OriginalLengthTooSmall {
                captured: captured_length,
                original: original_length,
            });
        }
        Ok(Self {
            timestamp,
            captured_length,
            original_length,
            link_type,
            interface: None,
            direction: None,
            bytes,
        })
    }

    pub fn captured_length(&self) -> u32 {
        self.captured_length
    }

    pub fn original_length(&self) -> u32 {
        self.original_length
    }

    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }
}

/// Inclusive capture-time bounds selecting which frames a command keeps.
///
/// Bounds compare against frame timestamps at full [`SystemTime`] precision;
/// fractional endpoints are never rounded. Both endpoints are inclusive, and
/// either side may be left open. A frame whose record carries no timestamp
/// never satisfies bounds, so commands that keep timestamp-less frames must
/// not apply bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeBounds {
    start: Option<SystemTime>,
    end: Option<SystemTime>,
}

impl TimeBounds {
    /// Bounds over `[start, end]`; either side may be `None` for an open end.
    /// Reversed bounds are rejected rather than matching nothing.
    pub fn new(start: Option<SystemTime>, end: Option<SystemTime>) -> Result<Self, Error> {
        if let (Some(start), Some(end)) = (start, end)
            && start > end
        {
            return Err(Error::ReversedTimeBounds { start, end });
        }
        Ok(Self { start, end })
    }

    /// The inclusive lower bound, if any.
    pub fn start(&self) -> Option<SystemTime> {
        self.start
    }

    /// The inclusive upper bound, if any.
    pub fn end(&self) -> Option<SystemTime> {
        self.end
    }

    /// Whether `timestamp` lies within the bounds; `None` never does.
    /// The check is a pure comparison, so capture timestamps may regress.
    pub fn contains(&self, timestamp: Option<SystemTime>) -> bool {
        timestamp.is_some_and(|timestamp| {
            self.start.is_none_or(|start| timestamp >= start)
                && self.end.is_none_or(|end| timestamp <= end)
        })
    }
}

impl<'de> Deserialize<'de> for Frame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Record {
            timestamp: Option<SystemTime>,
            captured_length: u32,
            original_length: u32,
            link_type: LinkType,
            interface: Option<GlobalInterfaceId>,
            direction: Option<Direction>,
            bytes: Bytes,
        }

        let record = Record::deserialize(deserializer)?;
        let mut frame = Frame::try_with_optional_timestamp(
            record.timestamp,
            record.link_type,
            record.captured_length,
            record.original_length,
            record.bytes,
        )
        .map_err(serde::de::Error::custom)?;
        frame.interface = record.interface;
        frame.direction = record.direction;
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn time_bounds_are_inclusive_at_representable_submicrosecond_precision() {
        let start = SystemTime::UNIX_EPOCH + Duration::new(10, 500_000_000);
        let end = SystemTime::UNIX_EPOCH + Duration::new(10, 900_000_100);
        let bounds = TimeBounds::new(Some(start), Some(end)).unwrap();
        assert!(bounds.contains(Some(start)));
        assert!(bounds.contains(Some(end)));
        assert!(!bounds.contains(Some(start - Duration::from_nanos(100))));
        assert!(!bounds.contains(Some(end + Duration::from_nanos(100))));
        assert!(!bounds.contains(None));
    }

    #[test]
    fn one_sided_time_bounds_leave_the_other_end_open() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let start_only = TimeBounds::new(Some(start), None).unwrap();
        assert!(start_only.contains(Some(start)));
        assert!(!start_only.contains(Some(start - Duration::from_nanos(100))));

        let stop_only = TimeBounds::new(None, Some(start)).unwrap();
        assert!(stop_only.contains(Some(start)));
        assert!(!stop_only.contains(Some(start + Duration::from_nanos(100))));
    }

    #[test]
    fn reversed_time_bounds_are_rejected() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        assert!(matches!(
            TimeBounds::new(Some(start), Some(start - Duration::from_nanos(100))),
            Err(Error::ReversedTimeBounds { .. })
        ));
        assert!(TimeBounds::new(Some(start), Some(start)).is_ok());
    }
}
