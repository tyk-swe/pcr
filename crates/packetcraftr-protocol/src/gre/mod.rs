// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Generic Routing Encapsulation protocol model.

mod model;

#[cfg(test)]
mod tests;

pub use model::Gre;
pub(crate) use model::GreCodec;
