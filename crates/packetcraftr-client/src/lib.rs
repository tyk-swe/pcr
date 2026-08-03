// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Policy-gated packet transmission and response exchange.

mod address;
mod evidence;
pub mod exchange;
mod materialize;
pub mod policy;
pub mod send;
pub mod target;
mod validation;

pub use send::contract::ClientError as Error;

mod client;
mod planning;
mod stats;
#[cfg(test)]
mod tests;

pub use client::Client;
pub use stats::Stats;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_net::{
    Error as LiveIoError,
    capture::{CaptureProvider, CaptureStatistics},
    link::LinkMode,
    route::{
        InterfaceId, NeighborResolver, PlanOptions, PlannedRoute, RouteDecision, RouteProvider,
    },
    transmit::{PacketIo, TransmissionFrame},
};
use packetcraftr_packet::{
    Packet,
    build::{Builder, BuiltPacket},
    decode::{DecodeOptions, Dissector},
    registry::ProtocolRegistry,
    semantics::BuiltinProtocol,
    template::PacketTemplate,
};

use self::exchange::{
    ExchangeOptions, ExchangeResult, ExchangeTransaction, PlannedExchangePacket, PreparedExchange,
    PreparedExchangePacket, WorkflowResponseMatcher,
};
use self::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    patch_builtin_ethernet, require_fixed_width_link_materialization,
};
use self::policy::TrafficPolicyError;
use self::send::{ClientError, SendOptions, SendReport};
use self::target::{
    HostnameResolver, IpVersion, LiveTarget, ResolvedTarget, TargetResolutionError,
};
use self::validation::{validate_mtu, validate_send_report};
