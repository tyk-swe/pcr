// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    Error as LiveIoError,
    capture::CaptureQueueLimits,
    interface::Id as InterfaceId,
    platform::live_capture::NativeCaptureParts,
    transmit::{IoSendReport, Layer2Frame},
};

pub(in crate::platform) fn open_capture(
    interface: &InterfaceId,
    limits: CaptureQueueLimits,
    capture_filter: Option<&str>,
    netmask: Option<u32>,
    promiscuous: bool,
) -> Result<NativeCaptureParts, LiveIoError> {
    let _ = (interface, limits, capture_filter, netmask, promiscuous);
    Err(LiveIoError::Unsupported {
        message: "native Windows Layer 2 I/O supports only x86_64-pc-windows-msvc".to_owned(),
    })
}

pub(in crate::platform) fn send_layer2(
    frame: Layer2Frame<'_>,
) -> Result<IoSendReport, LiveIoError> {
    let _ = frame;
    Err(LiveIoError::Unsupported {
        message: "native Windows Layer 2 I/O supports only x86_64-pc-windows-msvc".to_owned(),
    })
}
