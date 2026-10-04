// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Resource ceilings and running budgets for capture streams and readers.

use serde::{Deserialize, Serialize};

use crate::frame::DEFAULT_MAX_SIZE;

use super::error::Error;

/// Default maximum number of interface descriptions retained per PCAPNG section.
pub const DEFAULT_MAX_INTERFACES_PER_SECTION: usize = 4_096;
/// Default maximum interface descriptions retained across all PCAPNG sections.
pub const DEFAULT_MAX_TOTAL_INTERFACES: usize = 65_536;
/// Default maximum metadata blocks consumed before one packet is returned.
pub const DEFAULT_MAX_METADATA_BLOCKS_PER_FRAME: usize = 4_096;
/// Default maximum metadata bytes consumed before one packet is returned.
pub const DEFAULT_MAX_METADATA_BYTES_PER_FRAME: usize = 64 * 1024 * 1024;
/// Default maximum options retained from one PCAPNG block.
pub const DEFAULT_MAX_OPTIONS_PER_BLOCK: usize = 1_024;
/// Default maximum frames accepted by one streaming capture writer or copy.
pub const DEFAULT_MAX_STREAM_FRAMES: u64 = 10_000;
/// Default maximum captured payload bytes accepted by one streaming writer or copy.
pub const DEFAULT_MAX_STREAM_BYTES: u64 = 256 * 1024 * 1024;

/// Aggregate frame and byte ceilings for a streaming capture operation.
/// Writers charge captured payload; fidelity-preserving `rewrite` and `select`
/// charge all source bytes, including headers, options and metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_frames: u64,
    pub max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_MAX_STREAM_FRAMES,
            max_bytes: DEFAULT_MAX_STREAM_BYTES,
        }
    }
}

impl Limits {
    /// Rejects a zero ceiling, which would refuse every frame of the stream.
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
        ] {
            if value == 0 {
                return Err(Error::InvalidLimit { field, value });
            }
        }
        Ok(())
    }
}

/// The frames and captured bytes one stream has charged against its
/// [`Limits`].
///
/// A charge that would exceed either ceiling fails and leaves the budget
/// unchanged.
///
/// ```rust
/// use packetcraftr_core::capture_file::{Budget, Error, Limits};
///
/// let mut budget = Budget::new(Limits { max_frames: 1, max_bytes: 64 })?;
/// budget.charge(60)?;
/// assert!(matches!(budget.charge(1), Err(Error::FrameLimitExceeded { .. })));
/// assert_eq!((budget.frames(), budget.captured_bytes()), (1, 60));
/// # Ok::<(), Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    limits: Limits,
    frames: u64,
    captured_bytes: u64,
}

impl Budget {
    /// An empty budget for `limits`, after [`Limits::validate`] accepts them.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        Ok(Self {
            limits,
            frames: 0,
            captured_bytes: 0,
        })
    }

    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Frames charged so far.
    #[must_use]
    pub fn frames(&self) -> u64 {
        self.frames
    }

    /// Captured payload bytes charged so far.
    #[must_use]
    pub fn captured_bytes(&self) -> u64 {
        self.captured_bytes
    }

    /// A budget that has already charged `frames` and `captured_bytes`.
    #[cfg(test)]
    pub(super) fn charged(limits: Limits, frames: u64, captured_bytes: u64) -> Self {
        Self {
            limits,
            frames,
            captured_bytes,
        }
    }

    /// Charges one frame of `frame_bytes` captured bytes.
    pub fn charge(&mut self, frame_bytes: u32) -> Result<(), Error> {
        *self = self.after(frame_bytes)?;
        Ok(())
    }

    /// The budget after charging one frame, without changing this one, so a
    /// caller can check a frame before committing its output.
    pub fn after(&self, frame_bytes: u32) -> Result<Self, Error> {
        let frames = self
            .frames
            .checked_add(1)
            .ok_or(Error::FrameLimitExceeded {
                actual: u64::MAX,
                limit: self.limits.max_frames,
            })?;
        if frames > self.limits.max_frames {
            return Err(Error::FrameLimitExceeded {
                actual: frames,
                limit: self.limits.max_frames,
            });
        }

        let captured_bytes = self
            .captured_bytes
            .checked_add(u64::from(frame_bytes))
            .ok_or(Error::StreamByteLimitExceeded {
                actual: u64::MAX,
                limit: self.limits.max_bytes,
            })?;
        if captured_bytes > self.limits.max_bytes {
            return Err(Error::StreamByteLimitExceeded {
                actual: captured_bytes,
                limit: self.limits.max_bytes,
            });
        }

        Ok(Self {
            frames,
            captured_bytes,
            ..*self
        })
    }
}

/// Resource ceilings applied while streaming an offline capture.
///
/// Limits are enforced where their corresponding input is encountered. A zero
/// value therefore disables that class of input rather than being rejected
/// uniformly during construction.
///
/// ```rust
/// use std::io::Cursor;
/// use packetcraftr_core::capture_file::{Reader, ReaderLimits, Writer};
/// use packetcraftr_core::frame::LinkType;
///
/// let bytes = Writer::pcap(Vec::new(), LinkType::ETHERNET)?.into_inner();
/// let options = ReaderLimits {
///     max_size: 64 * 1024,
///     ..ReaderLimits::default()
/// };
/// let _reader = Reader::with_limits(Cursor::new(bytes), options)?;
/// # Ok::<(), packetcraftr_core::capture_file::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderLimits {
    /// Maximum packet or PCAPNG block size, in bytes.
    pub max_size: usize,
    pub max_interfaces_per_section: usize,
    pub max_total_interfaces: usize,
    pub max_metadata_blocks_per_frame: usize,
    pub max_metadata_bytes_per_frame: usize,
    /// Maximum options retained from one PCAPNG section, interface, or packet
    /// block. Each retained option costs more than its four-byte wire header,
    /// so this bounds the block's decoded size independently of `max_size`.
    pub max_options_per_block: usize,
}

impl Default for ReaderLimits {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_SIZE,
            max_interfaces_per_section: DEFAULT_MAX_INTERFACES_PER_SECTION,
            max_total_interfaces: DEFAULT_MAX_TOTAL_INTERFACES,
            max_metadata_blocks_per_frame: DEFAULT_MAX_METADATA_BLOCKS_PER_FRAME,
            max_metadata_bytes_per_frame: DEFAULT_MAX_METADATA_BYTES_PER_FRAME,
            max_options_per_block: DEFAULT_MAX_OPTIONS_PER_BLOCK,
        }
    }
}
