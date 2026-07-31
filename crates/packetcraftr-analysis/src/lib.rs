// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded offline capture analysis over dissected frames.
//!
//! This crate owns the read → dissect → index → filter → dispatch loop the
//! offline analysis commands share, and the adapters that map decoded layers
//! onto the session crate's reassembly inputs. Everything here is offline by
//! design: there is no resolver, route, capture, or transmission seam, so
//! analysis needs no authorization gates and runs in every build profile.
//!
//! That separation is why this is a crate rather than a module: it depends on
//! neither `packetcraftr-client` nor `packetcraftr-net`, so a live seam added
//! here fails to build instead of quietly bypassing an authorization gate.
//!
//! Conversation indices are assigned in first-seen order over the whole
//! capture, before any display filter runs, so an index one command reports
//! is the index another command extracts. Reassembly, by contrast, consumes
//! only the frames the filter keeps, so a run narrowed to one conversation
//! buffers only that conversation.

#![forbid(unsafe_code)]

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use thiserror::Error;

use packetcraftr_budget::Deadline;
use packetcraftr_capture::{
    DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, Error as CaptureError, Reader,
};
use packetcraftr_error::{BoundaryError, Classification, Classified, Kind};
use packetcraftr_packet::decode::{
    DecodedPacket, Decoder, Error as DecodeError, Options as DecodeOptions,
};
use packetcraftr_packet::filter::{Context as FilterContext, Filter};
use packetcraftr_packet::{
    Packet,
    layer::{Layer, Padding, Raw},
    registry::ProtocolRegistry,
};
use packetcraftr_protocol::gre::Gre;
use packetcraftr_protocol::ipv6::Fragment as Ipv6Fragment;
use packetcraftr_protocol::link::{Vlan, Vlan8021ad};
use packetcraftr_protocol::network::{Ipv4, Ipv6};
use packetcraftr_protocol::transport::{Tcp, Udp};
use packetcraftr_protocol::tunnel::{Ah, Erspan, Geneve, L2tpv3, Mpls, Pppoe, Vxlan};
use packetcraftr_session::ReassemblyLimits;
use packetcraftr_session::fragment::{
    DatagramKey as FragmentKey, Event as FragmentEvent, Fragment, OverlapPolicy,
    Reassembler as FragmentReassembler,
};
use packetcraftr_session::tcp::{
    Error as SessionTcpError, Event as TcpEvent, FlowKey, Reassembler as TcpReassembler, Segment,
};

mod error;
pub mod expert;
pub mod follow;
mod pipeline;
mod session_index;
pub mod stats;
#[cfg(test)]
mod tests;

pub use error::AnalysisError as Error;
pub use pipeline::{
    AnalysisLimits as Limits, AnalysisOptions as Options, AnalysisSummary as Summary, FrameRecord,
    run,
};
pub use session_index::{
    AnalysisScope, CanonicalFlow, ScopeComponent, StreamIndex, ip_fragment, tcp_segment, udp_flow,
};

use error::AnalysisError;
