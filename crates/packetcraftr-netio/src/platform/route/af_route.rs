// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Passive macOS route/interface adapter backed by `getifaddrs(3)` and routing sockets.
//! It performs no neighbor discovery, capture, or transmission.

mod enumeration;
mod parser;
mod query;

use crate::interface;

pub(in crate::platform) use query::{interface_route, route};

pub(in crate::platform) fn interfaces() -> Result<Vec<interface::Info>, interface::Error> {
    enumeration::interfaces().map_err(interface::Error::native)
}
