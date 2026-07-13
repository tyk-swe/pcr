// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capture::Frame;
use crate::error::{Category, Classification, Classified, Kind};
use crate::net::{
    CaptureOptions, CaptureOverflowPolicy, CaptureQueueLimits, CaptureSession, CaptureStatistics,
    CapturedFrame, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES, ExchangeIo,
    IoSendReport, LiveIoError, MAX_CAPTURE_TIMEOUT, MaterializedRoute, NeighborError,
    NeighborResolver, PacketIo, PlanError, PlanOptions, PlannedRoute, RoutePlanner, RouteProvider,
    TransmissionFrame,
};
use crate::packet::internal::{
    BuildContext, BuildError, BuildOptions, Builder, BuiltPacket, DEFAULT_MAX_TEMPLATE_PACKETS,
    DecodeOptions, DecodedPacket, Dissector, FieldValue, Packet, PacketTemplate, Padding,
    ProtocolRegistry,
};
use crate::protocol::internal::Ethernet;

include!("internal/stats.rs");
include!("internal/policy.rs");
include!("internal/target.rs");
include!("internal/policy_impl.rs");
include!("internal/send.rs");
include!("internal/exchange.rs");
include!("internal/client.rs");
include!("internal/helpers.rs");
include!("internal/tests.rs");
