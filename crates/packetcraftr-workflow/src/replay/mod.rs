// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, policy-gated capture replay over injectable timing and I/O seams.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use thiserror::Error;

use super::clock::Clock as WorkflowClock;
use super::deadline::{Deadline, DeadlineExceeded};
use packetcraftr_capture::{
    DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, Error as CaptureError, Format,
    Frame, Interface, LinkType, Reader,
};
use packetcraftr_model::error::{Classification, Classified, Kind};
use packetcraftr_net::{
    Error as LiveIoError, link::LinkMode, route::InterfaceId, transmit::IoSendReport,
};
use packetcraftr_packet::build::{
    Builder, Context as BuildContext, Mode as BuildMode, Options as BuildOptions,
};
use packetcraftr_packet::decode::{Decoder, Options as DecodeOptions};
use packetcraftr_packet::{catalog::ProtocolCatalogSnapshot, codec::NetworkEnvelope};

mod authorizer;
mod engine;
mod error;
mod model;
#[cfg(test)]
mod tests;
mod wire;

pub use authorizer::SystemAuthorizer;
pub use engine::replay_capture as run;
pub use error::ReplayError as Error;
pub use model::{
    MAX_REPLAY_DURATION, ReplayAuthorizationContext as AuthorizationContext,
    ReplayAuthorizer as Authorizer, ReplayFrameEvidence as FrameEvidence, ReplayLimits as Limits,
    ReplayOptions as Options, ReplaySummary as Summary, ReplayTiming as Timing,
    ReplayTransmission as Transmission, ReplayTransmitter as Transmitter,
};
pub use wire::replay_network_envelope as network_envelope;

#[cfg(test)]
use engine::replay_capture;
use error::ReplayError;
use model::{
    ReplayAuthorizationContext, ReplayAuthorizer, ReplayFrameEvidence, ReplayOptions,
    ReplaySummary, ReplayTransmitter,
};
#[cfg(test)]
use model::{ReplayLimits, ReplayTiming};
