// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Codecs preserve unknown and malformed bytes.

pub mod application;
pub mod builtin;
mod capabilities;
pub mod capture;
mod catalog;
pub use capabilities::{MESSAGE_PROTOCOLS, MessageProtocol};
mod common;
pub(crate) mod framing;
mod message;
pub use message::Records;
pub mod headers;
pub mod link;
mod matcher;
pub mod network;
pub mod response_identity;
pub mod semantics;
pub mod transport;
pub mod tunnel;

pub use catalog::{BuiltinProtocol, UnknownProtocolName};
pub use common::{ChecksumAccumulator, checksum, checksum_parts};
pub(crate) use common::{network_from_addresses, transport_checksum};

pub use matcher::{
    IcmpErrorKind, QuotedProbe, QuotedTransport, SctpResponseKind, quoted_icmp_error, quoted_probe,
    sctp_response_kind, transport_tuple_reversed,
};
