// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Passive macOS route/interface adapter backed by `getifaddrs(3)` and routing sockets.
//! It performs no neighbor discovery, capture, or transmission.

#![allow(unsafe_code)]

mod enumeration;
mod parser;
mod query;

pub(super) use enumeration::interfaces;
pub(super) use query::{interface_route, route};
