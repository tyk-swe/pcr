// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use thiserror::Error as ThisError;

use packetcraftr_core::error::{BoundaryError, Classification, Classified, Context};
use packetcraftr_netio::Error as LiveIoError;

use crate::{policy, target};

#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Target(#[from] target::Error),
    #[error(transparent)]
    Plan(#[from] packetcraftr_netio::route::Error),
    #[error(transparent)]
    Neighbor(#[from] packetcraftr_netio::neighbor::Error),
    #[error(transparent)]
    Build(#[from] packetcraftr_core::build::Error),
    #[error(transparent)]
    Policy(#[from] policy::Error),
    #[error(transparent)]
    Io(#[from] LiveIoError),
    #[error("{operation}; capture shutdown also failed: {shutdown}")]
    OperationAndCaptureShutdown {
        operation: LiveIoError,
        shutdown: LiveIoError,
    },
    #[error("progressive output failed: {source}")]
    Output {
        #[source]
        source: Box<packetcraftr_core::error::BoundaryError>,
    },
    #[error("progressive output failed: {output}; capture shutdown also failed: {shutdown}")]
    OutputAndCaptureShutdown {
        output: Box<packetcraftr_core::error::BoundaryError>,
        shutdown: LiveIoError,
    },
    #[error("exchange events are incoherent: {message}")]
    InvalidExchangeEvents { message: String },
    #[error("exchange packets selected different interfaces or link modes")]
    HeterogeneousExchangeRoute,
    #[error("packet template expansion failed: {message}")]
    Template { message: String },
    #[error("could not materialize {field} on layer {layer}: {message}")]
    PacketMaterialization {
        layer: usize,
        field: &'static str,
        message: String,
    },
    #[error(
        "network packet length {actual} exceeds route MTU {mtu}; apply an explicit fragmentation transform"
    )]
    PacketExceedsMtu { actual: usize, mtu: u32 },
    #[error("invalid exchange option {field}: {message}")]
    InvalidExchangeOption {
        field: &'static str,
        message: String,
    },
    #[error("invalid {field}: {message}")]
    InvalidRequest {
        field: &'static str,
        message: String,
    },
    #[error("worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("execution failed at {context}: {source}")]
    Execution {
        context: Context,
        #[source]
        source: Box<BoundaryError>,
    },
    #[error("clock failed at {context}: {message}")]
    Clock { context: Context, message: String },
    #[error("executor returned invalid evidence at {context}: {message}")]
    InvalidEvidence { context: Context, message: String },
    #[error("statistic accounting overflowed at {context}")]
    StatisticsOverflow { context: Context },
    #[error("DNS query construction failed: {0}")]
    DnsQuery(#[source] crate::dns::WireError),
    #[error(transparent)]
    FuzzCampaign(#[from] packetcraftr_core::fuzz::Error),
}

impl From<packetcraftr_core::budget::DeadlineExceeded> for Error {
    fn from(error: packetcraftr_core::budget::DeadlineExceeded) -> Self {
        Self::DurationLimit {
            actual: error.actual,
            limit: error.limit,
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Target(error) => error.classification(),
            Self::Plan(error) => error.classification(),
            Self::Neighbor(error) => error.classification(),
            Self::Build(error) => error.classification(),
            Self::Policy(error) => error.classification(),
            Self::Io(error) => error.classification(),
            Self::OperationAndCaptureShutdown { operation, .. } => operation.classification(),
            Self::Output { source } => source.classification(),
            Self::OutputAndCaptureShutdown { output, .. } => output.classification(),
            Self::InvalidExchangeEvents { .. } => Classification::new(
                "internal.exchange_event_coherence",
                Some("collect every exchange event once in publication order"),
            ),
            Self::HeterogeneousExchangeRoute => Classification::new(
                "cli.heterogeneous_exchange_route",
                Some("split the exchange so every packet uses the same interface and link mode"),
            ),
            Self::Template { .. } => Classification::new(
                "packet.template",
                Some("reduce or correct the bounded packet-template expansion"),
            ),
            Self::PacketMaterialization { .. } => Classification::new(
                "packet.materialization",
                Some(
                    "correct the route-dependent packet fields; post-build shape changes are rejected",
                ),
            ),
            Self::PacketExceedsMtu { .. } => Classification::new(
                "packet.mtu",
                Some("reduce the network packet or apply an explicit fragmentation transform"),
            ),
            Self::InvalidExchangeOption { .. } => Classification::new(
                "cli.exchange_limit",
                Some(
                    "use finite exchange timeout and retention limits no larger than the aggregate capture ceiling",
                ),
            ),
            Self::InvalidRequest { .. } => Classification::new(
                "cli.live_limit",
                Some("use a valid finite non-zero live request value within the documented limit"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.duration_limit",
                Some(
                    "reduce the operation workload or rate delay, or deliberately raise the finite duration limit",
                ),
            ),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => Classification::new(
                "io.clock",
                Some("inspect the timer and account for traffic already transmitted"),
            ),
            Self::InvalidEvidence { .. } => Classification::new(
                "internal.live_evidence",
                Some(
                    "treat the live operation as incomplete because executor evidence was inconsistent",
                ),
            ),
            Self::StatisticsOverflow { .. } => Classification::new(
                "internal.live_statistics",
                Some(
                    "treat the live operation as incomplete because statistic accounting overflowed",
                ),
            ),
            Self::DnsQuery(_) => Classification::new(
                "packet.dns_query",
                Some("use a bounded ASCII DNS name and a supported query type"),
            ),
            Self::FuzzCampaign(error) => error.classification(),
        }
    }

    fn context(&self) -> Context {
        match self {
            Self::Target(error) => error.context(),
            Self::Plan(error) => error.context(),
            Self::Neighbor(error) => error.context(),
            Self::Build(error) => error.context(),
            Self::Policy(error) => error.context(),
            Self::Io(error) => error.context(),
            Self::OperationAndCaptureShutdown { operation, .. } => operation.context(),
            Self::Output { source } => source.context(),
            Self::OutputAndCaptureShutdown { output, .. } => output.context(),
            Self::Execution { context, .. }
            | Self::Clock { context, .. }
            | Self::InvalidEvidence { context, .. }
            | Self::StatisticsOverflow { context } => *context,
            Self::FuzzCampaign(error) => error.context(),
            _ => Context::default(),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Target(error) => error.causes(),
            Self::Plan(error) => error.causes(),
            Self::Neighbor(error) => error.causes(),
            Self::Build(error) => error.causes(),
            Self::Policy(error) => error.causes(),
            Self::Io(error) => error.causes(),
            Self::OperationAndCaptureShutdown {
                operation,
                shutdown,
            } => vec![operation.to_string(), shutdown.to_string()],
            Self::Output { source } => source.causes(),
            Self::OutputAndCaptureShutdown { output, shutdown } => {
                let mut causes = output.causes();
                if causes.is_empty() {
                    causes.push(output.to_string());
                }
                causes.push(shutdown.to_string());
                causes
            }
            Self::Execution { source, .. } => source.causes(),
            Self::FuzzCampaign(error) => error.causes(),
            _ => Vec::new(),
        }
    }
}
