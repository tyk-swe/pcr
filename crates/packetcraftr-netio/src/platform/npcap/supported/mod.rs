// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Npcap implementation for the pinned x86_64 MSVC target.

#![allow(unsafe_code)]

#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
mod abi;
#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
mod capture;
#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
mod error;
#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
mod handles;
#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
mod loader;
#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
mod transmit;
#[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
mod unsupported;

#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
pub(super) use capture::open_capture;
#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
pub(super) use transmit::send_layer2;
#[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
pub(super) use unsupported::{open_capture, send_layer2};
