// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, capture-before-send ARP and IPv6 Neighbor Discovery.

#![forbid(unsafe_code)]

mod cache;
mod error;
mod evidence;
mod model;
mod options;
mod provider;
mod wire;

pub use error::Error;
pub use model::{Request, Resolution, VlanKind, VlanTag};
pub use options::Options;
pub use provider::{ActiveResolver, Resolver, SystemResolver};

pub(crate) use model::MAX_VLAN_TAGS;
