// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IPv6 extension-header models.

mod fragment;
mod options;
mod srh;

#[cfg(test)]
mod tests;

pub use fragment::Ipv6Fragment as Fragment;
pub(crate) use fragment::Ipv6FragmentCodec;
pub use options::{DestinationOptions, HopByHop};
pub(crate) use options::{DestinationOptionsCodec, HopByHopCodec};
pub use srh::SegmentRoutingHeader;
pub(crate) use srh::SegmentRoutingHeaderCodec;
