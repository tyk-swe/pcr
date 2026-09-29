// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Crate-private FFI and reviewed-unsafe-code boundary.

#[cfg(native_layer2)]
mod capture;
mod common;
mod dispatch;
mod execution_context;
#[cfg(native_route)]
mod interface;
#[cfg(native_route)]
mod route;
#[cfg(native_send)]
mod transmit;

#[cfg(not(native_layer2))]
pub(crate) use dispatch::unsupported;
#[cfg(native_send)]
pub(crate) use dispatch::verify_interface_identity;
pub(crate) use dispatch::{interface_route, interfaces, route, send_layer2, send_layer3};
#[cfg(native_layer2)]
pub(crate) use dispatch::{open_capture, timestamp_types, validate_capture_filter};
pub(crate) use execution_context::{ExecutionContext, current as execution_context};
