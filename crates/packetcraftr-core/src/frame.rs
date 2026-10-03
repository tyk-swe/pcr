// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::error::{Classification, Classified, Kind};

pub const DEFAULT_MAX_SIZE: usize = 16 * 1024 * 1024;

/// Open numeric libpcap link-layer type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LinkType(pub u32);

impl std::fmt::Display for LinkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Lengths {
    pub captured: u32,
    pub original: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

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
                Kind::Usage,
                Some("order the bounds so the earlier time comes first"),
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Frame {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<SystemTime>,
    captured_length: u32,
    original_length: u32,
    pub link_type: LinkType,
    /// Capture-wide interface index, normalized across PCAPNG sections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<u32>,
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
        lengths: Lengths,
        bytes: impl Into<Bytes>,
    ) -> Result<Self, Error> {
        Self::try_with_optional_timestamp(Some(timestamp), link_type, lengths, bytes)
    }

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
        Self::try_with_optional_timestamp(
            timestamp,
            link_type,
            Lengths {
                captured: length,
                original: length,
            },
            bytes,
        )
    }

    pub fn try_with_optional_timestamp(
        timestamp: Option<SystemTime>,
        link_type: LinkType,
        lengths: Lengths,
        bytes: impl Into<Bytes>,
    ) -> Result<Self, Error> {
        let bytes = bytes.into();
        if usize::try_from(lengths.captured) != Ok(bytes.len()) {
            return Err(Error::CapturedLengthMismatch {
                declared: lengths.captured,
                actual: bytes.len(),
            });
        }
        if lengths.original < lengths.captured {
            return Err(Error::OriginalLengthTooSmall {
                captured: lengths.captured,
                original: lengths.original,
            });
        }
        Ok(Self {
            timestamp,
            captured_length: lengths.captured,
            original_length: lengths.original,
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

    pub fn is_truncated(&self) -> bool {
        self.captured_length < self.original_length
    }

    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }
}

/// Splits `time` into whole Unix seconds, floored, and the nanoseconds past that second.
pub(crate) fn unix_floor(time: SystemTime) -> (i128, u32) {
    // seconds come from a `u64` and `subsec_nanos` is below one billion, so nothing can overflow
    match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (i128::from(elapsed.as_secs()), elapsed.subsec_nanos()),
        Err(error) => {
            let elapsed = error.duration();
            if elapsed.subsec_nanos() == 0 {
                (-i128::from(elapsed.as_secs()), 0)
            } else {
                (
                    -i128::from(elapsed.as_secs()) - 1,
                    1_000_000_000 - elapsed.subsec_nanos(),
                )
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeBounds {
    start: Option<SystemTime>,
    end: Option<SystemTime>,
}

impl TimeBounds {
    /// Reversed bounds are rejected rather than matching nothing.
    pub fn new(start: Option<SystemTime>, end: Option<SystemTime>) -> Result<Self, Error> {
        if let (Some(start), Some(end)) = (start, end)
            && start > end
        {
            return Err(Error::ReversedTimeBounds { start, end });
        }
        Ok(Self { start, end })
    }

    pub fn start(&self) -> Option<SystemTime> {
        self.start
    }

    pub fn end(&self) -> Option<SystemTime> {
        self.end
    }

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
            interface: Option<u32>,
            direction: Option<Direction>,
            bytes: Bytes,
        }

        let record = Record::deserialize(deserializer)?;
        let mut frame = Self::try_with_optional_timestamp(
            record.timestamp,
            record.link_type,
            Lengths {
                captured: record.captured_length,
                original: record.original_length,
            },
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
    fn unix_floor_rounds_instants_before_the_epoch_down() {
        let at =
            |seconds, nanoseconds| unix_floor(UNIX_EPOCH + Duration::new(seconds, nanoseconds));
        let before =
            |seconds, nanoseconds| unix_floor(UNIX_EPOCH - Duration::new(seconds, nanoseconds));
        assert_eq!(at(0, 0), (0, 0));
        assert_eq!(at(7, 125_000_000), (7, 125_000_000));
        assert_eq!(before(2, 0), (-2, 0));
        assert_eq!(before(0, 1), (-1, 999_999_999));
        assert_eq!(before(1, 250_000_000), (-2, 750_000_000));
    }
}
