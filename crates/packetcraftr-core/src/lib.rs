// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Runtime-neutral packet mechanics and bounded offline analysis.
//!
//! This is the portable foundation of PacketcraftR. It contains no resolver,
//! route lookup, live capture, or transmission seam; those belong to
//! `packetcraftr-netio` and the policy-gated `packetcraftr` workflows.

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
pub mod protocol;
mod protocol_catalog;
pub mod registry;
#[doc(hidden)]
pub mod semantics;
pub mod template;

pub use model::{Packet, PacketError as Error};
