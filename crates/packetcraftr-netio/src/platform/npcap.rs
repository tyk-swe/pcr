// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-loaded Npcap adapter for Windows.

#![allow(unsafe_code)]

use super::live_capture::NativeCaptureParts;
use crate::{
    Error,
    capture::Limits,
    interface::Id as InterfaceId,
    transmit::{self, Layer2Frame},
};

#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
mod supported;

pub(super) fn open_capture(
    interface: &InterfaceId,
    limits: Limits,
    capture_filter: Option<&str>,
    netmask: Option<u32>,
    promiscuous: bool,
) -> Result<NativeCaptureParts, Error> {
    #[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
    {
        supported::open_capture(interface, limits, capture_filter, netmask, promiscuous)
    }
    #[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
    {
        let _ = (interface, limits, capture_filter, netmask, promiscuous);
        Err(Error::Unsupported {
            message: "native Windows Layer 2 I/O supports only x86_64-pc-windows-msvc".to_owned(),
        })
    }
}

pub(super) fn send_layer2(frame: Layer2Frame<'_>) -> Result<transmit::Report, Error> {
    #[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
    {
        supported::send_layer2(frame)
    }
    #[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
    {
        let _ = frame;
        Err(Error::Unsupported {
            message: "native Windows Layer 2 I/O supports only x86_64-pc-windows-msvc".to_owned(),
        })
    }
}
