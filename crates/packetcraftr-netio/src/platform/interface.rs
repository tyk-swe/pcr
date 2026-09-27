// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interface backends: enumeration through route netlink on Linux,
//! `getifaddrs(3)` on macOS, and IP Helper on Windows, which the same
//! target's route backend also reads; and `identity`, the per-send check that
//! an interface kept its name and index.

#[cfg(target_os = "macos")]
pub(in crate::platform) mod af_route;
#[cfg(native_send)]
pub(in crate::platform) mod identity;
#[cfg(target_os = "windows")]
pub(in crate::platform) mod iphelper;
#[cfg(target_os = "linux")]
pub(in crate::platform) mod netlink;
