// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(target_os = "macos")]
pub(in crate::platform) mod af_route;
#[cfg(native_send)]
pub(in crate::platform) mod identity;
#[cfg(target_os = "windows")]
pub(in crate::platform) mod iphelper;
#[cfg(target_os = "linux")]
pub(in crate::platform) mod netlink;
