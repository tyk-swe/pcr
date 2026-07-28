// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-loaded Npcap adapter for Windows.

#![allow(unsafe_code)]

use super::live_capture::NativeCaptureParts;
use crate::{
    Error as LiveIoError,
    capture::CaptureQueueLimits,
    route::InterfaceId,
    transmit::{IoSendReport, Layer2Frame},
};

#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
mod supported;

pub(super) fn open_capture(
    interface: &InterfaceId,
    limits: CaptureQueueLimits,
) -> Result<NativeCaptureParts, LiveIoError> {
    #[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
    {
        supported::open_capture(interface, limits)
    }
    #[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
    {
        let _ = (interface, limits);
        Err(LiveIoError::Unsupported {
            message: "native Windows Layer 2 I/O supports only x86_64-pc-windows-msvc".to_owned(),
        })
    }
}

pub(super) fn send_layer2(frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    #[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
    {
        supported::send_layer2(frame)
    }
    #[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
    {
        let _ = frame;
        Err(LiveIoError::Unsupported {
            message: "native Windows Layer 2 I/O supports only x86_64-pc-windows-msvc".to_owned(),
        })
    }
}
