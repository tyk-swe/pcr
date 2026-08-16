// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Npcap implementation for the pinned x86_64 MSVC target.

#![allow(unsafe_code)]

use super::NativeCaptureParts;
use crate::{
    Error as LiveIoError,
    capture::CaptureQueueLimits,
    interface::Id as InterfaceId,
    transmit::{IoSendReport, Layer2Frame},
};

mod abi;
mod capture;
mod error;
mod handles;
mod loader;
mod transmit;

pub(super) fn open_capture(
    interface: &InterfaceId,
    limits: CaptureQueueLimits,
    capture_filter: Option<&str>,
    netmask: Option<u32>,
) -> Result<NativeCaptureParts, LiveIoError> {
    capture::open_capture(interface, limits, capture_filter, netmask)
}

pub(super) fn send_layer2(frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    transmit::send_layer2(frame)
}
