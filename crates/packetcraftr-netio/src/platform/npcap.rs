// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-loaded Npcap adapter for Windows (x86_64-pc-windows-msvc).

mod abi;
mod capture;
mod error;
mod handles;
mod loader;
mod transmit;

pub(super) use capture::open_capture;
pub(super) use transmit::send_layer2;
