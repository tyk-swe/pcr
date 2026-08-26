// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Runtime-neutral packet mechanics and bounded offline analysis.
//!
//! This portable foundation has no resolver, route lookup, live-capture, or
//! transmission seam. Provider contracts and native I/O live in
//! `packetcraftr-netio`; authorization-gated live workflows live in
//! `packetcraftr`.

pub mod analysis;
pub mod budget;
pub mod build;
pub mod codec;
pub mod decode;
pub mod diagnostic;
pub mod document;
pub mod error;
pub mod expression;
pub mod field;
pub mod filter;
pub mod frame;
pub mod fuzz;
pub mod layer;
pub mod layout;
pub mod matcher;
mod model;
/// Cross-crate seam for the `packetcraftr` workflow crate. Hidden from the
/// docs and outside the semver contract.
#[doc(hidden)]
pub mod progress;
pub mod protocol;
mod protocol_catalog;
pub mod registry;
/// Cross-crate seam for the `packetcraftr` workflow crate. Hidden from the
/// docs and outside the semver contract.
#[doc(hidden)]
pub mod semantics;
pub mod template;

pub use model::{Error, Packet};
