// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Built-in protocol models and deterministic registration.

pub mod builtin;
pub mod capture;
mod common;
pub mod icmp;
pub mod ipv6;
pub mod link;
mod matcher;
pub mod network;
mod raw;
pub mod support;
pub mod transport;
