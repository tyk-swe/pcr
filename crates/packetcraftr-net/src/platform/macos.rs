// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! macOS route and interface adapter backed by `getifaddrs(3)` and a routing
//! socket. Route lookup is passive: it does not perform neighbor discovery,
//! capture, or transmission.

#![allow(unsafe_code)]

mod enumeration;
mod parser;
mod query;
#[cfg(test)]
mod tests;

pub(super) use enumeration::interfaces;
pub(super) use query::{interface_route, route};
