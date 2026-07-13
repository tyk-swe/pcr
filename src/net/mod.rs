// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live network interfaces, routing, neighbor discovery, transmission, and capture.
//!
//! Native handles and platform-specific representations remain behind the private
//! `platform` boundary. Public contracts are grouped by responsibility and use
//! concise names within their owning namespace.

#[path = "neighbor/mod.rs"]
mod neighbor_impl;
mod platform;
#[path = "provider.rs"]
mod provider_impl;
#[path = "route/mod.rs"]
mod route_impl;

/// Errors shared by live interface, transmission, and capture providers.
pub use provider_impl::LiveIoError as Error;

/// Interface discovery and portable interface descriptions.
pub mod interface {
    pub use super::provider_impl::{
        InterfaceAddress as Address, InterfaceFlags as Flags, InterfaceInfo as Info,
        InterfaceProvider as Provider, SystemInterfaceProvider as SystemProvider,
    };
    pub use super::route_impl::InterfaceId as Id;
}

/// Link-layer addressing and transmission capabilities.
pub mod link {
    pub use super::route_impl::{LinkCapability as Capability, LinkMode as Mode, MacAddress};
}

/// Passive route selection, planning, and materialization.
pub mod route {
    pub use super::route_impl::{
        DestinationScope as Scope, MaterializedRoute as Materialized,
        NativeRouteError as SystemError, PlanError as Error, PlanOptions as Options,
        PlannedRoute as Plan, RouteDecision as Decision, RoutePlanner as Planner,
        RouteProvider as Provider, RouteSelectionReason as SelectionReason,
        SystemRouteProvider as SystemProvider,
    };
}

/// Active ARP/NDP resolution and its bounded evidence.
pub mod neighbor {
    pub use super::neighbor_impl::{
        ActiveNeighborResolver as ActiveResolver, NeighborResolutionOptions as Options,
        SystemNeighborResolver as SystemResolver,
    };
    pub use super::route_impl::{
        NeighborError as Error, NeighborRequest as Request, NeighborResolution as Resolution,
        NeighborResolver as Resolver, NeighborVlanKind as VlanKind, NeighborVlanTag as VlanTag,
    };
}

/// Typed Layer 2 and Layer 3 transmission contracts.
pub mod transmit {
    pub use super::provider_impl::{
        DispatchPacketIo as Dispatch, IoSendReport as Report, Layer2Frame,
        Layer2Io as Layer2Sender, Layer3Frame, Layer3Io as Layer3Sender, PacketIo as Sender,
        SystemLayer2Io as SystemLayer2, SystemLayer3Io as SystemLayer3, TransmissionFrame as Frame,
    };
}

/// Owned live-capture sessions and bounded queue configuration.
pub mod capture {
    pub use super::provider_impl::{
        CaptureEvidenceCompleteness as Completeness, CaptureFilter as Filter, CaptureMode as Mode,
        CaptureOptions as Options, CaptureOverflowPolicy as OverflowPolicy,
        CaptureProvider as Provider, CaptureQueueLimits as Limits, CaptureSession as Session,
        CaptureStatistics as Statistics, CapturedFrame as Captured, MAX_CAPTURE_FILTER_BYTES,
        SystemCaptureProvider as SystemProvider, SystemCaptureSession as SystemSession,
    };
}

/// Composition contracts for capture-before-send exchanges.
pub mod exchange {
    use super::provider_impl::{
        CaptureOptions, CaptureProvider, CaptureQueueLimits, IoSendReport, LiveIoError, PacketIo,
        TransmissionFrame,
    };
    use super::route_impl::PlannedRoute;

    /// A provider that supports both transmission and capture.
    pub use super::provider_impl::ExchangeIo as Io;

    /// Composes separately owned transmission and capture providers.
    #[derive(Clone, Copy, Debug)]
    pub struct Composite<S, C> {
        sender: S,
        capture: C,
    }

    impl<S, C> Composite<S, C> {
        pub fn new(sender: S, capture: C) -> Self {
            Self { sender, capture }
        }

        pub fn sender(&self) -> &S {
            &self.sender
        }

        pub fn capture(&self) -> &C {
            &self.capture
        }

        pub fn into_parts(self) -> (S, C) {
            (self.sender, self.capture)
        }
    }

    impl<S, C> PacketIo for Composite<S, C>
    where
        S: PacketIo,
        C: Send + Sync,
    {
        fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
            self.sender.send(frame)
        }
    }

    impl<S, C> CaptureProvider for Composite<S, C>
    where
        S: Send + Sync,
        C: CaptureProvider,
    {
        type Capture = C::Capture;

        fn arm_capture(
            &self,
            route: &PlannedRoute,
            limits: CaptureQueueLimits,
        ) -> Result<Self::Capture, LiveIoError> {
            self.capture.arm_capture(route, limits)
        }

        fn arm_capture_with_options(
            &self,
            route: &PlannedRoute,
            limits: CaptureQueueLimits,
            options: CaptureOptions,
        ) -> Result<Self::Capture, LiveIoError> {
            self.capture
                .arm_capture_with_options(route, limits, options)
        }
    }
}

// The implementation still uses its established vocabulary internally. These
// aliases are crate-private so downstream users see only the canonical modules
// above while the native implementation remains a mechanical, reviewable move.
#[cfg(all(test, feature = "native-layer2"))]
pub(crate) use provider_impl::CaptureEvidenceCompleteness;
#[cfg(any(test, feature = "native-layer2"))]
pub(crate) use provider_impl::CaptureMode;
#[cfg(feature = "native-layer3")]
pub(crate) use provider_impl::Layer3Frame;
pub(crate) use provider_impl::{
    CaptureOptions, CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession,
    CaptureStatistics, CapturedFrame, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES,
    DispatchPacketIo, ExchangeIo, InterfaceInfo, InterfaceProvider, IoSendReport, Layer2Frame,
    Layer2Io, LiveIoError, MAX_CAPTURE_TIMEOUT, PacketIo, SystemCaptureProvider,
    SystemInterfaceProvider, SystemLayer2Io, SystemLayer3Io, TransmissionFrame,
};
#[cfg(any(feature = "native-route", all(feature = "live", windows), test))]
pub(crate) use provider_impl::{InterfaceAddress, InterfaceFlags};
pub(crate) use route_impl::{
    DestinationScope, InterfaceId, LinkCapability, LinkMode, MAX_NEIGHBOR_VLAN_TAGS, MacAddress,
    MaterializedRoute, NativeRouteError, NeighborError, NeighborRequest, NeighborResolution,
    NeighborResolver, NeighborVlanKind, NeighborVlanTag, PlanError, PlanOptions, PlannedRoute,
    RouteDecision, RoutePlanner, RouteProvider, RouteSelectionReason, SystemRouteProvider,
};
