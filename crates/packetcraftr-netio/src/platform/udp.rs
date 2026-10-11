// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(target_os = "windows"))]
pub(in crate::platform) mod stdlib;
#[cfg(target_os = "windows")]
pub(in crate::platform) mod winsock;
