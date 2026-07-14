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
use crate::packet::build::{
    Builder, Context as BuildContext, Mode as BuildMode, Options as BuildOptions,
};
use crate::packet::decode::{Decoder, Options as DecodeOptions};
use crate::packet::{codec::NetworkEnvelope, registry::ProtocolRegistry};

mod adapter;
mod engine;
mod error;
mod model;
#[cfg(test)]
mod tests;
mod wire;

pub use adapter::{SystemAuthorizer, SystemTransmitter};
pub use engine::replay_capture as run;
pub use error::ReplayError as Error;
pub use model::{
    MAX_REPLAY_DURATION, ReplayAuthorizationError as AuthorizationError,
    ReplayAuthorizer as Authorizer, ReplayFrameEvidence as FrameEvidence, ReplayLimits as Limits,
    ReplayOptions as Options, ReplaySummary as Summary, ReplayTiming as Timing,
    ReplayTransmission as Transmission, ReplayTransmitter as Transmitter,
};

#[cfg(test)]
use engine::replay_capture;
use error::ReplayError;
use model::{
    ReplayAuthorizationError, ReplayAuthorizer, ReplayFrameEvidence, ReplayOptions, ReplaySummary,
    ReplayTransmission, ReplayTransmitter,
};
#[cfg(test)]
use model::{ReplayLimits, ReplayTiming};
