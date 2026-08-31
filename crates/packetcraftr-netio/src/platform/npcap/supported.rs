// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Npcap implementation for the pinned x86_64 MSVC target.

mod abi;
mod capture;
mod error;
mod handles;
mod loader;
mod transmit;

pub(super) use capture::open_capture;
pub(super) use transmit::send_layer2;
