// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::Client;
use super::evidence::reserve_capture_evidence;
use super::exchange::{
    CaptureGuard, ExchangeAccumulator, ExchangeOptions, ExchangeProcessContext,
    ExchangeProcessOutcome, ExchangeResult, MAX_EXCHANGE_TIMEOUT, PreparedExchangePacket,
    WorkflowPromotionContext,
};
use super::materialize::patch_builtin_ethernet;
use super::send::{ClientError, SendOptions};
use packetcraftr_model::error::{Category, Classified, Kind};
use packetcraftr_model::{Frame, LinkType, ProviderId, RegistrationOrigin};
use packetcraftr_net::{
    Error as LiveIoError,
    capture::{
        CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession,
        CaptureStatistics, CapturedFrame, DEFAULT_CAPTURE_QUEUE_BYTES,
        DEFAULT_CAPTURE_QUEUE_FRAMES,
    },
    link::{LinkCapability, LinkMode, MacAddress},
    neighbor::Error as NeighborError,
    route::{
        DestinationScope, InterfaceId, MaterializedRoute, NeighborRequest, NeighborResolution,
        NeighborResolver, PlanError, PlanOptions, PlannedRoute, RouteDecision, RouteProvider,
        RouteSelectionReason,
    },
    transmit::{IoSendReport, PacketIo, TransmissionFrame},
};
use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuildOptions, Builder, BuiltPacket},
    catalog::{
        ProtocolBindingRegistration, ProtocolCatalogSnapshot, ProtocolRegistration,
        ProtocolRegistrationSet,
    },
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, NativeLayerCodec, NativeLayerDecodeContext,
        NativeLayerEncodeContext,
    },
    decode::Dissector,
    field::{FieldKind, FieldValue, WireValue},
    layer::{
        FieldConstraints, FieldError, FieldId, FieldSchema, Layer, LayerSchema, ProtocolId, Raw,
        ValidatedFieldSet,
    },
    matcher::{MatchResult, NativeResponseMatcher},
    provider::{NativeProtocolImplementation, NativeProtocolProvider, ProviderProtocolKey},
    template::{PacketTemplate, TemplateValues},
};
use packetcraftr_policy::target::{Hostname, HostnameResolver, LiveTarget, TargetResolutionError};
use packetcraftr_policy::{TrafficPolicy, TrafficPolicyError};
use packetcraftr_protocols::{
    builtin::{Module as BuiltinProtocols, catalog as default_catalog},
    icmp::Icmpv4,
    ipv6::SegmentRoutingHeader,
    link::{Arp, Ethernet, Vlan, Vlan8021ad},
    network::{Ipv4, Ipv6},
    transport::Udp,
};

use support::{
    ChangedWireIo, CountingNeighbors, CountingRoutes, CustomRouteLayer,
    DeadlineConsumingExchangeIo, DestinationRoutes, DropObservedCapture, EndlessCaptureIo,
    FailingNeighbors, FixedRoutes, InterfaceRoutes, MacSensitiveLayer, PanicShutdownCapture,
    PartialIo, ReadinessAndShutdownFailCapture, ReadinessAndShutdownFailIo,
    RecordingHostnameResolver, RecordingIo, RejectingPacketIo, ScriptedExchangeIo, SlowRoutes,
    SlowSendIo, UnmarkedExchangeIo, canonical_link_intent_packets, catalog_with_mac_sensitive,
    exchange_with_capture_statistics, packet, prepared_exchange_packet, route,
};

mod support;

mod authorization;
mod deadlines;
mod exchange_lifecycle;
mod planning;
mod promotion;
mod sending;
mod target_limits;
