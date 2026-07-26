// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native composition of the active neighbor resolver.

#![forbid(unsafe_code)]

use packetcraftr_net::neighbor::ActiveNeighborResolver;

use crate::capture::SystemProvider as SystemCaptureProvider;
use crate::transmit::SystemLayer2;

/// Active ARP/Neighbor Discovery resolver composed from the native Layer 2
/// sender and the native capture provider.
pub type SystemNeighborResolver = ActiveNeighborResolver<SystemLayer2, SystemCaptureProvider>;

/// Concise alias inside the neighbor namespace.
pub type SystemResolver = SystemNeighborResolver;
