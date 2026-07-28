// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, policy-gated capture replay over injectable timing and I/O seams.
//!
//! Replay retransmits frames from a capture file to reproduce a previously
//! observed exchange against an authorized destination, which is how a
//! protocol bug captured once is turned into a repeatable test. Every frame is
//! authorized individually, and replaying a frame whose dissection preserved
//! malformed bytes additionally requires the explicit malformed-traffic
//! opt-ins.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use thiserror::Error;

use super::clock::Clock as WorkflowClock;
use super::deadline::{Deadline, DeadlineExceeded};
use packetcraftr_capture::{
    DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, Error as CaptureError, Format,
    Frame, Interface, LinkType, Reader,
};
use packetcraftr_error::{Classification, Classified, Kind};
use packetcraftr_net::{
    Error as LiveIoError,
    interface::{InterfaceInfo, InterfaceProvider, SystemInterfaceProvider},
    link::{LinkCapability, LinkMode},
    route::{
        DestinationScope, InterfaceId, MaterializedRoute, PlannedRoute, RouteDecision,
        RouteProvider, RouteSelectionReason, SystemRouteProvider,
    },
    transmit::{
        DispatchPacketIo, IoSendReport, PacketIo, SystemLayer2Io, SystemLayer3Io, TransmissionFrame,
    },
};
use packetcraftr_packet::build::{
    Builder, Context as BuildContext, Mode as BuildMode, Options as BuildOptions,
};
use packetcraftr_packet::decode::{Decoder, Options as DecodeOptions};
use packetcraftr_packet::{codec::NetworkEnvelope, registry::ProtocolRegistry};

mod adapter;
mod engine;
mod error;
mod model;
#[cfg(test)]
mod tests;
mod wire;

pub use adapter::{SystemAuthorizer, SystemTransmitter};
pub use engine::{replay_capture as run, replay_capture_with_selector as run_with_selector};
pub use error::ReplayError as Error;
pub use model::{
    MAX_REPLAY_DURATION, ReplayAuthorizationContext as AuthorizationContext,
    ReplayAuthorizer as Authorizer, ReplayFrameEvidence as FrameEvidence, ReplayLimits as Limits,
    ReplayOptions as Options, ReplaySelector as Selector, ReplaySummary as Summary,
    ReplayTiming as Timing, ReplayTransmission as Transmission, ReplayTransmitter as Transmitter,
};

#[cfg(test)]
use engine::{replay_capture, replay_capture_with_selector};
use error::ReplayError;
use model::{
    ReplayAuthorizationContext, ReplayAuthorizer, ReplayFrameEvidence, ReplayOptions,
    ReplaySelector, ReplaySummary, ReplayTransmission, ReplayTransmitter,
};
#[cfg(test)]
use model::{ReplayLimits, ReplayTiming};
