// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IPv6 extension-header models.

mod model;

pub use model::{DestinationOptions, HopByHop, Ipv6Fragment as Fragment, SegmentRoutingHeader};
pub(crate) use model::{
    DestinationOptionsCodec, HopByHopCodec, Ipv6FragmentCodec, SegmentRoutingHeaderCodec,
};
