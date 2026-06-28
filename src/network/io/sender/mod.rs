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

pub use control::{
    emission_accounting, validate_transmission_policy, EmissionAccounting, SendControlError,
    TransmissionPolicy,
};
pub use error::{
    ExecutorError, FragmentError, HeaderError, InterfaceError, Ipv4Error, Ipv6Error, Layer2Error,
    PayloadError, PlannerError, Result as SenderResult, SenderError,
};
pub use executor::execute_transmission;
#[cfg(any(test, feature = "test_utils"))]
pub use executor::test_utils;
pub(crate) use metrics::emit_metrics_snapshot;
pub use planner::{
    plan_transmission, plan_transmission_dry_run, plan_transmission_dry_run_with_policy,
    plan_transmission_with_interface, plan_transmission_with_interface_and_policy,
    plan_transmission_with_policy,
};
#[cfg(feature = "traceroute")]
pub(crate) use transport::{build_icmpv6_segment, build_tcp_segment};
#[cfg(feature = "scan")]
pub(crate) use transport::{build_tcp_segment_optimized, finalize_udp_checksum, tcp_flags_value};

// Re-export specific items for tests to use
#[doc(hidden)]
pub use transport::{build_transport_segment, TransportBuildError};

pub use types::{LinkType, NetworkTarget, PlanningMode, TransmissionPlan, TransmissionSummary};

#[cfg(test)]
mod tests;
