// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-loaded Npcap adapter for Windows.

#![allow(unsafe_code)]

mod supported;

pub(super) use supported::{open_capture, send_layer2};
