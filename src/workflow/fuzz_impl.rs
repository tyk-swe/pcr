// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, bounded, field-aware packet mutation.
//!
//! [`fuzz`] is deliberately offline: its signature has no resolver, route, or
//! native-I/O seam. [`fuzz_live`] is a separate, explicit entry point that
//! requires operation authorization and a capture-ready executor.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::clock::Clock;
use super::evidence::EvidenceBudget;
use super::push_diagnostic_once;
use crate::capture::{Frame, LinkType};
use crate::error::{Classification, Classified, Kind};
use crate::net::{
    CaptureStatistics, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES, ExchangeIo,
    MAX_CAPTURE_TIMEOUT, NeighborResolver, RouteProvider,
};
use crate::packet::internal::{
    BuildContext, BuildOptions, Builder, BuiltPacket, DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_MAX_TEMPLATE_PACKETS, DecodeOptions, DecodedPacket, Diagnostic, Dissector, FieldKind,
    FieldValue, Packet, PacketTemplate, ProtocolRegistry,
};

pub const DEFAULT_FUZZ_CASES: usize = 64;
pub const DEFAULT_MAX_FUZZ_CASES: usize = DEFAULT_MAX_TEMPLATE_PACKETS;
pub const MAX_FUZZ_CASES: usize = 100_000;
pub const DEFAULT_MAX_FUZZ_FIELD_BYTES: usize = 4 * 1024;
pub const MAX_FUZZ_FIELD_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_FUZZ_LIST_ITEMS: usize = 256;
pub const MAX_FUZZ_LIST_ITEMS: usize = 4_096;
pub const DEFAULT_MAX_FUZZ_SHRINK_STEPS: usize = 8;
pub const MAX_FUZZ_SHRINK_STEPS: usize = 64;
pub const MAX_FUZZ_RATE: u32 = 1_000_000;
pub const MAX_FUZZ_DURATION: Duration = MAX_CAPTURE_TIMEOUT;
pub const MAX_FUZZ_STRATEGIES: usize = 4;
pub const MAX_FUZZ_TARGET_FIELDS: usize = 4_096;

const SYNTHESIZED_ETHERNET_BYTES: u64 = 14;
const SPLITMIX_INCREMENT: u64 = 0x9e37_79b9_7f4a_7c15;
const CASE_DOMAIN: u64 = 0xd1b5_4a32_d192_ed03;

include!("fuzz/model.rs");
include!("fuzz/error.rs");
include!("fuzz/engine.rs");
include!("fuzz/mutation.rs");
include!("fuzz/execution.rs");
include!("fuzz/adapter.rs");
include!("fuzz/tests.rs");
