// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded offline capture analysis over dissected frames.
//!
//! This module owns the read → dissect → index → filter → dispatch loop the
//! offline analysis commands share, and the adapters that map decoded layers
//! onto the session crate's reassembly inputs. Everything here is offline by
//! design: there is no resolver, route, capture, or transmission seam, so
//! analysis needs no authorization gates and runs in every build profile.
//!
//! Conversation indices are assigned in first-seen order over the whole
//! capture, before any display filter runs, so an index one command reports
//! is the index another command extracts. Reassembly, by contrast, consumes
//! only the frames the filter keeps, so a run narrowed to one conversation
//! buffers only that conversation.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use thiserror::Error;

use packetcraftr_capture::{
    DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, Error as CaptureError, Reader,
};
use packetcraftr_error::{Classification, Classified, Kind};
use packetcraftr_packet::decode::{
    DecodedPacket, Decoder, Error as DecodeError, Options as DecodeOptions,
};
use packetcraftr_packet::filter::{Context as FilterContext, Filter};
use packetcraftr_packet::{
    Packet,
    layer::{Padding, Raw},
    registry::ProtocolRegistry,
};
use packetcraftr_protocol::ipv6::Fragment as Ipv6Fragment;
use packetcraftr_protocol::network::{Ipv4, Ipv6};
use packetcraftr_protocol::transport::{Tcp, Udp};
use packetcraftr_session::ReassemblyLimits;
use packetcraftr_session::fragment::{
    DatagramKey as FragmentKey, Event as FragmentEvent, Fragment, OverlapPolicy,
    Reassembler as FragmentReassembler,
};
use packetcraftr_session::tcp::{
    Event as TcpEvent, FlowKey, Reassembler as TcpReassembler, Segment,
};

use super::deadline::Deadline;

mod error;
mod pipeline;
mod session_index;
#[cfg(test)]
mod tests;

pub use error::AnalysisError as Error;
pub use pipeline::{
    AnalysisLimits as Limits, AnalysisOptions as Options, AnalysisSummary as Summary, FrameRecord,
    run,
};
pub use session_index::{CanonicalFlow, StreamIndex, ip_fragment, tcp_segment, udp_flow};

use error::AnalysisError;
