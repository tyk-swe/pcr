// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, policy-gated capture replay over injectable timing and I/O seams.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use thiserror::Error;

use super::clock::Clock as WorkflowClock;
use crate::capture::{
    DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, Error as CaptureError, Format,
    Frame, Interface, LinkType, Reader,
};
use crate::error::{Classification, Classified, Kind};
use crate::net::{
    DestinationScope, DispatchPacketIo, InterfaceId, InterfaceInfo, InterfaceProvider,
    IoSendReport, LinkCapability, LinkMode, LiveIoError, MaterializedRoute, PacketIo, PlannedRoute,
    RouteDecision, RouteProvider, RouteSelectionReason, SystemInterfaceProvider, SystemLayer2Io,
    SystemLayer3Io, SystemRouteProvider, TransmissionFrame,
};
use crate::packet::build::{
    Builder, Context as BuildContext, Mode as BuildMode, Options as BuildOptions,
};
use crate::packet::decode::{Decoder, Options as DecodeOptions};
use crate::packet::internal::{NetworkEnvelope, ProtocolRegistry};

#[path = "replay/adapter.rs"]
mod adapter;
#[path = "replay/engine.rs"]
mod engine;
#[path = "replay/error.rs"]
mod error;
#[path = "replay/model.rs"]
mod model;
#[cfg(test)]
#[path = "replay/tests.rs"]
mod tests;
#[path = "replay/wire.rs"]
mod wire;

pub use adapter::{SystemAuthorizer, SystemTransmitter};
pub use engine::replay_capture;
pub use error::ReplayError;
pub use model::{
    MAX_REPLAY_DURATION, ReplayAuthorizationError, ReplayAuthorizer, ReplayFrameEvidence,
    ReplayLimits, ReplayOptions, ReplaySummary, ReplayTiming, ReplayTransmission,
    ReplayTransmitter,
};
