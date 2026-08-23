// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned native capture worker and bounded queue shared by libpcap and Npcap.

#![forbid(unsafe_code)]

pub(super) use parts::{
    CaptureInterrupt, NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource,
    NativeCaptureStatistics, NativeCapturedPacket, canonical_link_type,
    validate_effective_snapshot_length,
};
pub(super) use session::NativeCaptureSession;
pub(super) use time::{monotonic_packet_time, system_time};

mod parts;
mod queue;
mod session;
mod time;
mod worker;
