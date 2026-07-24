// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::client::Client;
use super::exchange::{
    CaptureGuard, ExchangeAccumulator, ExchangeOptions, ExchangeProcessContext,
    ExchangeProcessOutcome, ExchangeResult, MAX_EXCHANGE_TIMEOUT, PreparedExchangePacket,
    WorkflowPromotionContext,
};
use super::helpers::{patch_builtin_ethernet, reserve_capture_evidence};
use super::policy::{TrafficPolicy, TrafficPolicyError};
use super::send::{ClientError, SendOptions};
use super::target::{
    Hostname, HostnameResolver, IpVersion, LiveTarget, ResolvedTarget, TargetResolutionError,
};
use crate::capture::{Frame, LinkType};
use crate::error::{Category, Classified, Kind};
use crate::net::{
    Error as LiveIoError,
    capture::{
        CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession,
        CaptureStatistics, CapturedFrame, DEFAULT_CAPTURE_QUEUE_BYTES,
        DEFAULT_CAPTURE_QUEUE_FRAMES,
    },
    link::{LinkCapability, LinkMode, MacAddress},
    neighbor::Error as NeighborError,
    route::{
        DestinationScope, InterfaceId, MaterializedRoute, NativeRouteError, NeighborResolver,
        PlanError, PlanOptions, PlannedRoute, RouteDecision, RouteProvider, RouteSelectionReason,
    },
    transmit::{IoSendReport, PacketIo, TransmissionFrame},
};
use crate::packet::{
    Packet,
    build::{BuildContext, BuildOptions, Builder, BuiltPacket},
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    decode::Dissector,
    field::{FieldKind, FieldValue, WireValue},
    layer::{FieldError, FieldSchema, Layer, LayerSchema, ProtocolId, Raw},
    matcher::{Matcher, Result as MatchResult},
    registry::RegistryBuilder,
    template::{PacketTemplate, TemplateValues},
};
use crate::protocol::{
    builtin::{Module as BuiltinProtocols, registry as default_registry},
    icmp::Icmpv4,
    ipv6::SegmentRoutingHeader,
    link::{Arp, Ethernet, Vlan, Vlan8021ad},
    network::{Ipv4, Ipv6},
    transport::Udp,
};

mod support;

use support::{
    ChangedWireIo, CountingNeighbors, CountingRoutes, CustomRouteLayer,
    DeadlineConsumingExchangeIo, DestinationRoutes, DropObservedCapture, EndlessCaptureIo,
    FailingNeighbors, FixedRoutes, InterfaceRoutes, MacSensitiveCodec, MacSensitiveLayer,
    MissingMonotonicIo, PanicShutdownCapture, PartialIo, ReadinessAndShutdownFailCapture,
    ReadinessAndShutdownFailIo, RecordingHostnameResolver, RecordingIo, RejectingPacketIo,
    ScriptedExchangeIo, SlowMatcher, SlowRoutes, SlowSendIo, UnmarkedExchangeIo,
    canonical_link_intent_packets, exchange_with_capture_statistics, packet,
    prepared_exchange_packet, route,
};

mod authorization;
mod deadlines;
mod exchange_lifecycle;
mod planning;
mod promotion;
mod sending;
mod target_limits;
