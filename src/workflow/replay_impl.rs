// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, policy-gated capture replay over injectable timing and I/O seams.

use std::error::Error;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::clock::Clock as WorkflowClock;
use crate::capture::{
    Error as CaptureError, Format, Frame, Interface, LinkType, Reader, DEFAULT_SIZE_LIMIT,
    DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES,
};
use crate::error::{Classification, Classified, Kind};
use crate::net::{
    DestinationScope, DispatchPacketIo, InterfaceId, InterfaceInfo, InterfaceProvider,
    IoSendReport, LinkCapability, LinkMode, LiveIoError, MaterializedRoute, PacketIo, PlannedRoute,
    RouteDecision, RouteProvider, RouteSelectionReason, SystemInterfaceProvider, SystemLayer2Io,
    SystemLayer3Io, SystemRouteProvider, TransmissionFrame, MAX_CAPTURE_TIMEOUT,
};
use crate::packet::build::{
    Builder, Context as BuildContext, Mode as BuildMode, Options as BuildOptions,
};
use crate::packet::decode::{Decoder, Options as DecodeOptions};
use crate::packet::internal::{NetworkEnvelope, ProtocolRegistry};

include!("replay/model.rs");
include!("replay/adapter.rs");
include!("replay/error.rs");
include!("replay/engine.rs");
include!("replay/wire.rs");
include!("replay/tests.rs");
