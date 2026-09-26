// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, capture-before-send ARP and IPv6 Neighbor Discovery.
//!
//! Resolution is active discovery: it arms capture and transmits a request,
//! so it runs only while materializing a route that policy already admitted.
//! The [`Client`](crate::Client) resolves over its own transmit and capture
//! providers, under the [`Options`] set with
//! [`Client::with_neighbor_options`](crate::Client::with_neighbor_options),
//! and keeps one cache for all of its operations.

mod cache;
mod error;
mod evidence;
mod model;
mod options;
mod resolver;
mod wire;

pub use error::Error;
pub use model::{Request, Resolution};
pub use options::Options;
pub(crate) use resolver::{Resolver, State};
