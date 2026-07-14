// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, bounded, field-aware packet mutation.
//!
//! [`run`] is deliberately offline: its signature has no resolver, route, or
//! native-I/O seam. [`run_live`] is a separate, explicit entry point that
//! requires operation authorization and a capture-ready executor.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::Serialize;
use thiserror::Error;

use super::clock::Clock;
use super::evidence::EvidenceBudget;
use super::push_diagnostic_once;
use crate::capture::{Frame, LinkType};
use crate::error::{Classification, Classified, Kind};
use crate::net::{
    capture::{CaptureStatistics, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES},
    exchange::ExchangeIo,
    route::{NeighborResolver, RouteProvider},
};
use crate::packet::{
    Packet,
    build::{BuildContext, BuildOptions, Builder, BuiltPacket, DEFAULT_MAX_PACKET_SIZE},
    decode::{DecodeOptions, DecodedPacket, Dissector},
    diagnostic::Diagnostic,
    field::{FieldKind, FieldValue},
    registry::ProtocolRegistry,
    template::{DEFAULT_MAX_TEMPLATE_PACKETS, PacketTemplate},
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
pub const MAX_FUZZ_DURATION: Duration = crate::net::capture::MAX_TIMEOUT;
pub const MAX_FUZZ_STRATEGIES: usize = 4;
pub const MAX_FUZZ_TARGET_FIELDS: usize = 4_096;

const SYNTHESIZED_ETHERNET_BYTES: u64 = 14;
const SPLITMIX_INCREMENT: u64 = 0x9e37_79b9_7f4a_7c15;
const CASE_DOMAIN: u64 = 0xd1b5_4a32_d192_ed03;

mod adapter;
mod engine;
mod error;
mod execution;
mod model;
mod mutation;
#[cfg(test)]
mod tests;

pub use adapter::{ClientExecutor, PolicyAuthorizer};
pub use engine::{fuzz as run, fuzz_live as run_live};
pub use error::FuzzError as Error;
pub use model::{
    FuzzAuthorizationError as AuthorizationError, FuzzAuthorizer as Authorizer, FuzzCase as Case,
    FuzzCaseExecution as Execution, FuzzCaseFailure as CaseFailure, FuzzCaseOutcome as CaseOutcome,
    FuzzExecutionCase as ExecutionCase, FuzzExecutionError as ExecutionError,
    FuzzExecutionStats as ExecutionStats, FuzzExecutor as Executor, FuzzLimits as Limits,
    FuzzLiveOptions as LiveOptions, FuzzMode as Mode, FuzzMutation as Mutation,
    FuzzReproduction as Reproduction, FuzzRequest as Request, FuzzResult as Result,
    FuzzStats as Stats, FuzzStrategy as Strategy, FuzzTarget as Target,
    FuzzTargetParseError as TargetParseError,
};

#[cfg(test)]
use engine::{fuzz, fuzz_live};
use error::FuzzError;
use model::{
    FuzzAuthorizationError, FuzzAuthorizer, FuzzCase, FuzzCaseExecution, FuzzCaseFailure,
    FuzzCaseOutcome, FuzzExecutionCase, FuzzExecutionError, FuzzExecutionStats, FuzzExecutor,
    FuzzLimits, FuzzLiveOptions, FuzzMode, FuzzMutation, FuzzReproduction, FuzzRequest, FuzzResult,
    FuzzStats, FuzzStrategy, FuzzTarget,
};
