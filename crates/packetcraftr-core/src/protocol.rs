// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Codecs preserve unknown and malformed bytes.

pub mod application;
pub mod builtin;
pub mod capture;
mod catalog;
mod common;
pub(crate) mod framing;
mod message;
pub use message::Records;
pub mod headers;
pub mod identity;
pub mod link;
mod matcher;
pub mod network;
pub mod semantics;
pub mod transport;
pub mod tunnel;

pub use catalog::{BuiltinProtocol, MatcherKind, UnknownProtocolName};
pub use common::{
    CHECKSUM_FAILURE_CODES, ChecksumAccumulator, GRE_CHECKSUM, ICMPV4_CHECKSUM, ICMPV6_CHECKSUM,
    IGMP_CHECKSUM, IPV4_CHECKSUM, SCTP_CHECKSUM, TCP_CHECKSUM, UDP_CHECKSUM, VRRP_CHECKSUM,
    checksum_parts,
};
pub(crate) use common::{network_from_addresses, transport_checksum_parts};
pub use framing::Framing;

pub use matcher::{
    IcmpErrorKind, QuotedProbe, QuotedTransport, SctpResponseKind, quoted_icmp_error, quoted_probe,
    sctp_response_kind, transport_tuple_reversed,
};
