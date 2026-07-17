//! IPv6 extension-header models.

mod model;

pub use model::{DestinationOptions, HopByHop, Ipv6Fragment as Fragment, SegmentRoutingHeader};
pub(crate) use model::{
    DestinationOptionsCodec, HopByHopCodec, Ipv6FragmentCodec, SegmentRoutingHeaderCodec,
};
