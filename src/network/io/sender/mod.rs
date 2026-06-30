// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

mod builder;
mod control;
mod error;
mod executor;
mod fragment;
mod header;
mod interface;
mod ipv4;
mod ipv6;
mod ipv6_ext;
mod layer2;
mod metrics;
mod payload;
mod planner;
mod transport;
mod types;

pub(crate) use executor::execute_transmission;

pub(crate) use metrics::emit_metrics_snapshot;
#[cfg(feature = "fuzz")]
pub(crate) use planner::plan_transmission;
pub(crate) use planner::{plan_transmission_dry_run_with_policy, plan_transmission_with_policy};
#[cfg(feature = "traceroute")]
pub(crate) use transport::{build_icmpv6_segment, build_tcp_segment};
#[cfg(feature = "scan")]
pub(crate) use transport::{build_tcp_segment_optimized, finalize_udp_checksum, tcp_flags_value};

pub(crate) use types::NetworkTransmissionPlan;
