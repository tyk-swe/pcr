// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Crate-private native adapter boundary.
//!
//! This directory is the only location in the crate permitted to contain FFI
//! or narrowly reviewed unsafe code. Public traits and values live in `io`.

#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(all(feature = "live", not(windows)))]
mod pnet_enumeration;
#[cfg(windows)]
mod windows;

use super::provider::{InterfaceInfo, LiveIoError};

#[cfg(all(feature = "live", not(windows)))]
pub(super) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    Ok(pnet_enumeration::interfaces())
}

#[cfg(all(feature = "live", windows))]
pub(super) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    Err(LiveIoError::Unsupported {
        message: "Windows interface enumeration is unavailable in the portable profile; use a PacketcraftR build with the Windows native adapter when available (Npcap is required only for native Layer 2 capture and injection)".to_owned(),
    })
}

#[cfg(not(feature = "live"))]
pub(super) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    Err(LiveIoError::Unsupported {
        message: "interface enumeration is unavailable without the live feature".to_owned(),
    })
}
