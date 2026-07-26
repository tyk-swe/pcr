// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Complete captured bytes and the link-layer metadata that describes them.

use std::time::SystemTime;

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::error::{Classification, Classified, Kind};

/// Default maximum captured bytes in one frame (16 MiB).
///
/// Offline capture records and live capture queues share this ceiling so a
/// captured frame can always be written back to a capture file.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

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

/// Frame length invariants rejected by construction, deserialization, and
/// revalidation. Capture formats classify their own parse failures; this
/// taxonomy stays independent of any container.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    #[error("captured frame contains {actual} bytes, exceeding the u32 capture-record limit")]
    CapturedLengthTooLarge { actual: usize },
    #[error("frame captured length says {declared} bytes but contains {actual}")]
    CapturedLengthMismatch { declared: u32, actual: usize },
    #[error("frame original length {original} is smaller than captured length {captured}")]
    OriginalLengthTooSmall { captured: u32, original: u32 },
}

impl Classified for FrameError {
    fn classification(&self) -> Classification {
        Classification::new(
            "packet.capture_file",
            Kind::Packet,
            Some("repair the malformed or unrepresentable capture record before processing it"),
        )
    }
}

/// Complete bytes and capture metadata, independent of successful dissection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Frame {
    pub timestamp: SystemTime,
    captured_length: u32,
    original_length: u32,
    pub link_type: LinkType,
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
    ) -> Result<Self, FrameError> {
        let bytes = bytes.into();
        let length =
            u32::try_from(bytes.len()).map_err(|_| FrameError::CapturedLengthTooLarge {
                actual: bytes.len(),
            })?;
        Ok(Self {
            timestamp,
            captured_length: length,
            original_length: length,
            link_type,
            interface: None,
            direction: None,
            bytes,
        })
    }

    pub fn try_with_lengths(
        timestamp: SystemTime,
        link_type: LinkType,
        captured_length: u32,
        original_length: u32,
        bytes: impl Into<Bytes>,
    ) -> Result<Self, FrameError> {
        let bytes = bytes.into();
        if bytes.len() != captured_length as usize {
            return Err(FrameError::CapturedLengthMismatch {
                declared: captured_length,
                actual: bytes.len(),
            });
        }
        if original_length < captured_length {
            return Err(FrameError::OriginalLengthTooSmall {
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

    pub fn validate(&self) -> Result<(), FrameError> {
        if self.bytes.len() != self.captured_length as usize {
            return Err(FrameError::CapturedLengthMismatch {
                declared: self.captured_length,
                actual: self.bytes.len(),
            });
        }
        if self.original_length < self.captured_length {
            return Err(FrameError::OriginalLengthTooSmall {
                captured: self.captured_length,
                original: self.original_length,
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for Frame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Record {
            timestamp: SystemTime,
            captured_length: u32,
            original_length: u32,
            link_type: LinkType,
            interface: Option<u32>,
            direction: Option<Direction>,
            bytes: Bytes,
        }

        let record = Record::deserialize(deserializer)?;
        let mut frame = Frame::try_with_lengths(
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

    #[test]
    fn deserialization_rejects_inconsistent_lengths() {
        let value = serde_json::json!({
            "timestamp": { "secs_since_epoch": 0, "nanos_since_epoch": 0 },
            "captured_length": 2,
            "original_length": 2,
            "link_type": 1,
            "bytes": [1]
        });
        assert!(serde_json::from_value::<Frame>(value).is_err());
    }

    #[test]
    fn bsd_raw_and_standard_raw_have_distinct_link_types() {
        assert_eq!(LinkType::BSD_RAW, LinkType(12));
        assert_eq!(LinkType::RAW, LinkType(101));
        assert_ne!(LinkType::BSD_RAW, LinkType::RAW);
    }

    #[test]
    fn constructors_preserve_length_invariants() {
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![1, 2]).unwrap();
        assert_eq!(frame.captured_length(), 2);
        assert_eq!(frame.original_length(), 2);
        assert_eq!(frame.bytes().as_ref(), &[1, 2]);
        assert!(frame.validate().is_ok());
    }

    #[test]
    fn frame_errors_classify_as_repairable_capture_records() {
        let error =
            Frame::try_with_lengths(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, 2, 1, vec![1, 2])
                .unwrap_err();
        assert_eq!(
            error,
            FrameError::OriginalLengthTooSmall {
                captured: 2,
                original: 1
            }
        );
        assert_eq!(error.classification().code, "packet.capture_file");
        assert_eq!(error.classification().kind, Kind::Packet);
    }
}
