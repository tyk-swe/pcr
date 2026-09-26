// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The route contract: passive route and interface lookups answered by a
//! [`Provider`], and the native [`SystemProvider`].
//!
//! Planning a packet's route from these answers belongs to
//! `packetcraftr::route`.

mod models;
#[cfg(native_route)]
pub(crate) mod normalize;
mod provider;

pub use models::{Decision, Provider, Scope, SelectionReason};
pub use provider::{SystemError, SystemProvider};
