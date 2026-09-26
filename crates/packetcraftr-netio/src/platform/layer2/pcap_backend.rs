// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! libpcap-backed Layer 2 capture and injection for Linux and macOS.

mod bpf;
mod capture;
mod transmit;

pub(in crate::platform) use capture::{open_capture, timestamp_types};
pub(in crate::platform) use transmit::send_layer2;
