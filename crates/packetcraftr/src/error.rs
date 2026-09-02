// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error as ThisError;

use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};
use packetcraftr_netio::Error as LiveIoError;

use crate::{policy, target};

#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Target(#[from] target::Error),
    /// Route planning or materialization failed, including active neighbor
    /// resolution performed while materializing the route.
    #[error(transparent)]
    Plan(#[from] packetcraftr_netio::route::Error),
    #[error(transparent)]
    Build(#[from] packetcraftr_core::build::Error),
    #[error(transparent)]
    Policy(#[from] policy::Error),
    #[error("permissively built packets require allow_permissive_live")]
    PermissiveLiveOptInRequired,
    #[error(transparent)]
    Io(#[from] LiveIoError),
    /// Boxed because this variant is the only one that carries two complete
    /// live-I/O failures, and no other workflow failure should make room for
    /// them.
    #[error("{operation}; capture shutdown also failed: {shutdown}")]
    OperationAndCaptureShutdown {
        operation: Box<LiveIoError>,
        shutdown: Box<LiveIoError>,
    },
    #[error("exchange progressive output failed: {source}")]
    ExchangeOutput {
        #[source]
        source: Box<packetcraftr_core::error::BoundaryError>,
    },
    #[error(
        "exchange progressive output failed: {output}; capture shutdown also failed: {shutdown}"
    )]
    ExchangeOutputAndCaptureShutdown {
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
}

/// A `cli.*` code means "caller or request error": the request that reached a
/// workflow was not something the workflow could run.
impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Target(error) => error.classification(),
            Self::Plan(error) => error.classification(),
            Self::Build(_) => Classification::new(
                "packet.build",
                Kind::Packet,
                Some(
                    "correct the packet fields or select permissive mode with the required live opt-ins",
                ),
            ),
            Self::Policy(error) => error.classification(),
            Self::PermissiveLiveOptInRequired => Classification::new(
                "policy.permissive_live_opt_in",
                Kind::Policy,
                Some(
                    "set the explicit per-operation malformed-live opt-in in addition to policy approval",
                ),
            ),
            Self::Io(error) => error.classification(),
            Self::OperationAndCaptureShutdown { operation, .. } => operation.classification(),
            Self::ExchangeOutput { source } => source.classification(),
            Self::ExchangeOutputAndCaptureShutdown { output, .. } => output.classification(),
            Self::InvalidExchangeEvents { .. } => Classification::new(
                "internal.exchange_event_coherence",
                Kind::Internal,
                Some("collect every exchange event once in publication order"),
            ),
            Self::HeterogeneousExchangeRoute => Classification::new(
                "cli.heterogeneous_exchange_route",
                Kind::Cli,
                Some("split the exchange so every packet uses the same interface and link mode"),
            ),
            Self::Template { .. } => Classification::new(
                "packet.template",
                Kind::Packet,
                Some("reduce or correct the bounded packet-template expansion"),
            ),
            Self::PacketMaterialization { .. } => Classification::new(
                "packet.materialization",
                Kind::Packet,
                Some(
                    "correct the route-dependent packet fields; post-build shape changes are rejected",
                ),
            ),
            Self::PacketExceedsMtu { .. } => Classification::new(
                "packet.mtu",
                Kind::Packet,
                Some("reduce the network packet or apply an explicit fragmentation transform"),
            ),
            Self::InvalidExchangeOption { .. } => Classification::new(
                "cli.exchange_limit",
                Kind::Cli,
                Some(
                    "use finite exchange timeout and retention limits no larger than the aggregate capture ceiling",
                ),
            ),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Target(error) => error.context(),
            Self::Plan(error) => error.context(),
            Self::Policy(error) => error.context(),
            Self::Io(error) => error.context(),
            Self::OperationAndCaptureShutdown { operation, .. } => operation.context(),
            Self::ExchangeOutput { source } => source.context(),
            Self::ExchangeOutputAndCaptureShutdown { output, .. } => output.context(),
            Self::Build(_)
            | Self::PermissiveLiveOptInRequired
            | Self::InvalidExchangeEvents { .. }
            | Self::HeterogeneousExchangeRoute
            | Self::Template { .. }
            | Self::PacketMaterialization { .. }
            | Self::PacketExceedsMtu { .. }
            | Self::InvalidExchangeOption { .. } => None,
        }
    }

    /// Walked from the retained `#[source]` chain. A transparent variant
    /// delegates, because its own `Display` is already the inner error's
    /// message; so does the boundary-sourced variant, whose [`BoundaryError`]
    /// carries a captured `causes` snapshot its own source chain does not
    /// hold. The two paired failures carry an operation and an unrelated
    /// cleanup at once, so neither has a single chain to walk.
    ///
    /// [`BoundaryError`]: packetcraftr_core::error::BoundaryError
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Target(error) => error.causes(),
            Self::Plan(error) => error.causes(),
            Self::Build(error) => error.causes(),
            Self::Policy(error) => error.causes(),
            Self::Io(error) => error.causes(),
            Self::ExchangeOutput { source } => source.causes(),
            Self::OperationAndCaptureShutdown {
                operation,
                shutdown,
            } => vec![operation.to_string(), shutdown.to_string()],
            Self::ExchangeOutputAndCaptureShutdown { output, shutdown } => {
                let mut causes = output.causes();
                if causes.is_empty() {
                    causes.push(output.to_string());
                }
                causes.push(shutdown.to_string());
                causes
            }
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}
