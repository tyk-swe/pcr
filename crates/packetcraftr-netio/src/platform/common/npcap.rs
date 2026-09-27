// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The runtime-loaded Npcap library for Windows (x86_64-pc-windows-msvc): its
//! ABI, loader, handles, and error mapping, shared by the Npcap capture and
//! transmit backends.

pub(in crate::platform) mod abi;
pub(in crate::platform) mod error;
pub(in crate::platform) mod handles;
pub(in crate::platform) mod loader;
