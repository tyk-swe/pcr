//! Internet Control Message Protocol models.

pub(crate) mod model;

pub use model::{Icmpv4, Icmpv6};
pub(crate) use model::{Icmpv4Codec, Icmpv6Codec};
