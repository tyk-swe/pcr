// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-neutral capture records and streaming offline capture I/O.

mod neighbor;
mod pcap;
mod platform;
mod provider;
mod route;

pub use crate::core::{CaptureDirection, CaptureRecordError, CapturedFrame, LinkType};
pub use neighbor::{ActiveNeighborResolver, NeighborResolutionOptions, SystemNeighborResolver};
pub use pcap::{
    CaptureError, CaptureFileFormat, CaptureReader, CaptureWriter, PcapEndianness, ReplayTiming,
    DEFAULT_CAPTURE_SIZE_LIMIT, DEFAULT_PCAPNG_INTERFACE_LIMIT,
    DEFAULT_PCAPNG_METADATA_BLOCK_LIMIT,
};
pub use provider::{
    CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession, CaptureStatistics,
    DispatchPacketIo, ExchangeIo, InterfaceAddress, InterfaceFlags, InterfaceInfo,
    InterfaceProvider, IoSendReport, Layer2Frame, Layer2Io, Layer3Frame, Layer3Io, LiveIoError,
    PacketIo, SystemCaptureProvider, SystemCaptureSession, SystemInterfaceProvider, SystemLayer2Io,
    SystemLayer3Io, TransmissionFrame, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES,
};
pub use route::{
    DestinationScope, InterfaceId, LinkCapability, LinkMode, MacAddress, MaterializedRoute,
    NativeRouteError, NeighborError, NeighborRequest, NeighborResolution, NeighborResolver,
    NeighborVlanKind, NeighborVlanTag, PlanError, PlanOptions, PlannedRoute, RouteDecision,
    RoutePlanner, RouteProvider, RouteSelectionReason, SystemRouteProvider, MAX_NEIGHBOR_VLAN_TAGS,
};
