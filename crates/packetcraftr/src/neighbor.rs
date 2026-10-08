// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, capture-before-send ARP and IPv6 Neighbor Discovery.

mod cache;
mod error;
mod evidence;
mod model;
mod options;
mod resolver;
mod wire;

pub use error::Error;
pub use model::{MAX_VLAN_TAGS, Request, Resolution};
pub use options::Options;
pub(crate) use resolver::{Resolver, State, request_frame};

// Allowance for one ARP request or NDP neighbor solicitation: Ethernet
// padding for ARP, a source link-address option for NDP, and the largest
// VLAN tag stack a route may add to either.
const VLAN_STACK_BYTES: u64 = 4 * MAX_VLAN_TAGS as u64;
pub(crate) const IPV4_REQUEST_BYTES: u64 = 60 + VLAN_STACK_BYTES;
pub(crate) const IPV6_REQUEST_BYTES: u64 = 14 + 40 + 32 + VLAN_STACK_BYTES;
