// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error as ThisError;

use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};
use packetcraftr_netio::Error as LiveIoError;

use crate::{policy, target};

/// Why preparing a live packet failed: the operation's cancellation, policy,
/// packet building and materialization, route planning (including neighbor
/// resolution), or a provider. Every workflow that transmits prepared packets
/// wraps it in its own error.
#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
    #[error(transparent)]
    Target(#[from] target::Error),
    /// Route planning or materialization failed, including active neighbor
    /// resolution performed while materializing the route.
    #[error(transparent)]
    Plan(#[from] crate::route::Error),
    #[error(transparent)]
    Build(#[from] packetcraftr_core::build::Error),
    #[error(transparent)]
    Policy(#[from] policy::Error),
    #[error(transparent)]
    Io(#[from] LiveIoError),
    #[error("packet template expansion failed: {message}")]
    Template {
        message: String,
        /// The expansion failure the template reported, when this refusal is
        /// not the workflow's own empty-expansion check.
        #[source]
        source: Option<packetcraftr_core::template::Error>,
    },
    #[error("could not materialize {field} on layer {layer}: {message}")]
    PacketMaterialization {
        layer: usize,
        field: &'static str,
        message: String,
        /// The packet-layer failure the materialization step ran into, when
        /// one exists; a missing route value is the packet's own refusal and
        /// has none.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    #[error(
        "network packet length {actual} exceeds route MTU {mtu}; apply an explicit fragmentation transform"
    )]
    PacketExceedsMtu { actual: usize, mtu: u32 },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
            Self::Target(error) => error.classification(),
            Self::Plan(error) => error.classification(),
            Self::Build(error) => error.classification(),
            Self::Policy(error) => error.classification(),
            Self::Io(error) => error.classification(),
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
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Target(error) => error.context(),
            Self::Plan(error) => error.context(),
            Self::Policy(error) => error.context(),
            Self::Io(error) => error.context(),
            Self::Build(_)
            | Self::Template { .. }
            | Self::PacketMaterialization { .. }
            | Self::PacketExceedsMtu { .. }
            | Self::Cancelled(_) => None,
        }
    }

    /// Walks retained sources, delegating transparent errors.
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Target(error) => error.causes(),
            Self::Plan(error) => error.causes(),
            Self::Build(error) => error.causes(),
            Self::Policy(error) => error.causes(),
            Self::Io(error) => error.causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(source: std::convert::Infallible) -> Self {
        match source {}
    }
}
