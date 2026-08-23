// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! libpcap-backed Layer 2 capture and injection for Linux and macOS.

#![allow(unsafe_code)]

mod bpf;
mod capture;
mod transmit;

pub(super) use capture::open_capture;
pub(super) use transmit::send_layer2;
