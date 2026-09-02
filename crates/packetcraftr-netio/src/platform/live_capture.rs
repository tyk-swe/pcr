// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned native capture worker and bounded queue shared by libpcap and Npcap.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use bytes::Bytes;

use crate::{Error, capture::Metadata};

pub(super) use session::NativeCaptureSession;
pub(super) use time::{monotonic_packet_time, system_time};

mod queue;
mod session;
mod time;
mod worker;

pub(super) struct NativeCapturedPacket {
    pub timestamp: SystemTime,
    /// Conservative monotonic time derived from the kernel packet timestamp.
    pub received_at: Option<Instant>,
    pub captured_length: u32,
    pub original_length: u32,
    pub bytes: Bytes,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NativeCaptureStatistics {
    pub capture_dropped_frames: u32,
    pub network_dropped_frames: u32,
    pub interface_dropped_frames: u32,
}

pub(super) enum NativeCaptureEvent {
    Packet(NativeCapturedPacket),
    Timeout,
    Closed,
}

pub(super) trait NativeCaptureSource: Send {
    fn next_event(&mut self) -> Result<NativeCaptureEvent, Error>;
    fn statistics(&mut self) -> Result<NativeCaptureStatistics, Error>;
}

pub(super) trait CaptureInterrupt: Send + Sync {
    fn interrupt(&self);
}

pub(super) struct NativeCaptureParts {
    pub source: Box<dyn NativeCaptureSource>,
    pub interrupt: Arc<dyn CaptureInterrupt>,
    pub metadata: Metadata,
}
