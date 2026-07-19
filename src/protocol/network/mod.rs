//! Network-layer protocol models.

mod igmp;
mod model;

pub use igmp::Igmp;
pub(crate) use igmp::IgmpCodec;
pub use model::{Ipv4, Ipv6};
pub(crate) use model::{
    Ipv4Codec, Ipv4OptionsError, Ipv6Codec, RawIpCodec, encode_network,
    ipv4_source_route_destinations,
};
