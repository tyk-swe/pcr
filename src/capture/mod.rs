// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Runtime-neutral capture records and streaming offline capture I/O.

use std::time::SystemTime;

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};

mod pcap;

pub use pcap::{
    transcode, Endianness, Error, Format, Interface, Limits, Reader, TimestampResolution,
    TranscodeReport, Writer, DEFAULT_INTERFACE_LIMIT, DEFAULT_METADATA_BLOCK_LIMIT,
    DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, DEFAULT_TOTAL_INTERFACE_LIMIT,
};

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

/// Complete bytes and capture metadata, independent of successful dissection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Frame {
    pub timestamp: SystemTime,
    pub captured_length: u32,
    pub original_length: u32,
    pub link_type: LinkType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    pub bytes: Bytes,
}

impl Frame {
    pub fn new(
        timestamp: SystemTime,
        link_type: LinkType,
        bytes: impl Into<Bytes>,
    ) -> Result<Self, Error> {
        let bytes = bytes.into();
        let length = u32::try_from(bytes.len()).map_err(|_| Error::CapturedLengthTooLarge {
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
    ) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.len() != captured_length as usize {
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

    pub fn validate(&self) -> Result<(), Error> {
        if self.bytes.len() != self.captured_length as usize {
            return Err(Error::CapturedLengthMismatch {
                declared: self.captured_length,
                actual: self.bytes.len(),
            });
        }
        if self.original_length < self.captured_length {
            return Err(Error::OriginalLengthTooSmall {
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
    fn validation_catches_public_field_mutation() {
        let mut frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![1, 2]).unwrap();
        frame.captured_length = 1;
        assert!(matches!(
            frame.validate(),
            Err(Error::CapturedLengthMismatch {
                declared: 1,
                actual: 2
            })
        ));
    }
}
