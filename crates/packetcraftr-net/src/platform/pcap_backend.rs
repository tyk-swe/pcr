// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! libpcap-backed Layer 2 capture and injection for Linux and macOS.

#![allow(unsafe_code)]

mod bpf;
mod capture;
mod transmit;

pub(crate) use capture::open_capture;
pub(crate) use transmit::send_layer2;
