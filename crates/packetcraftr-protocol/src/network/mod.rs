// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Network-layer protocol models.

mod encode;
mod igmp;
mod ipv4;
mod ipv6;
mod raw_ip;

pub(crate) use encode::encode_network;
pub use igmp::Igmp;
pub(crate) use igmp::IgmpCodec;
pub use ipv4::Ipv4;
pub(crate) use ipv4::Ipv4Codec;
pub use ipv6::Ipv6;
pub(crate) use ipv6::Ipv6Codec;
pub(crate) use raw_ip::RawIpCodec;
