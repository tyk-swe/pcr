// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Crate-private FFI and reviewed-unsafe-code boundary.

#[cfg(native_layer2)]
pub(crate) mod capture;
mod common;
pub(crate) mod interface;
pub(crate) mod route;
pub(crate) mod transmit;
pub(crate) mod udp;
