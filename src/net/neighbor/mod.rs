// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, capture-before-send ARP and IPv6 Neighbor Discovery.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::capture::{Frame, LinkType};

use super::{
    CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession, CaptureStatistics,
    DestinationScope, InterfaceId, InterfaceInfo, InterfaceProvider, IoSendReport, Layer2Frame,
    Layer2Io, LinkCapability, LinkMode, LiveIoError, MacAddress, MaterializedRoute, NeighborError,
    NeighborRequest, NeighborResolution, NeighborResolver, NeighborVlanKind, NeighborVlanTag,
    PlannedRoute, RouteDecision, RouteSelectionReason, SystemCaptureProvider,
    SystemInterfaceProvider, SystemLayer2Io, MAX_NEIGHBOR_VLAN_TAGS,
};

// Active resolution is split by responsibility while retaining one private
// implementation scope for the cache, wire parser, and provider state machine.
include!("options.rs");
include!("cache.rs");
include!("wire.rs");
include!("provider.rs");
include!("tests.rs");
