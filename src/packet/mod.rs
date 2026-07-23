// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Runtime-neutral packet model, construction, decoding, and extension contracts.

pub mod build;
pub mod codec;
pub mod decode;
pub mod diagnostic;
pub mod document;
pub mod expression;
pub mod field;
pub mod layer;
pub mod layout;
pub mod matcher;
mod model;
mod protocol_catalog;
pub mod registry;
pub(crate) mod semantics;
pub mod template;

pub use model::{Packet, PacketError as Error};
