// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(target_os = "windows"))]
mod stdlib;
#[cfg(target_os = "windows")]
mod winsock;

#[cfg(not(target_os = "windows"))]
pub(crate) use stdlib::receive;
#[cfg(target_os = "windows")]
pub(crate) use winsock::receive;
