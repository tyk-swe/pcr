// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Codecs preserve unknown and malformed bytes.

pub mod application;
pub mod builtin;
pub mod capture;
mod catalog;
mod common;
pub mod headers;
pub mod link;
mod matcher;
pub mod network;
pub mod semantics;
pub mod transport;
pub mod tunnel;

pub use catalog::{BuiltinProtocol, UnknownProtocolName};
pub use common::{ChecksumAccumulator, checksum, checksum_parts};
pub(crate) use common::{network_from_addresses, transport_checksum};

pub use matcher::{
    IcmpErrorKind, QuotedTransport, quoted_icmp_error, quoted_udp_checksum,
    transport_tuple_reversed,
};
