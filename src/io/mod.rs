// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-neutral capture records and streaming offline capture I/O.

mod pcap;
mod route;

pub use crate::core::{CaptureDirection, CaptureRecordError, CapturedFrame, LinkType};
pub use pcap::{
    CaptureError, CaptureFileFormat, CaptureReader, CaptureWriter, PcapEndianness, ReplayTiming,
    DEFAULT_CAPTURE_SIZE_LIMIT, DEFAULT_PCAPNG_INTERFACE_LIMIT,
    DEFAULT_PCAPNG_METADATA_BLOCK_LIMIT,
};
pub use route::{
    DestinationScope, InterfaceId, LinkCapability, LinkMode, MacAddress, MaterializedRoute,
    NeighborError, NeighborResolver, PlanError, PlanOptions, PlannedRoute, RouteDecision,
    RoutePlanner, RouteProvider,
};
