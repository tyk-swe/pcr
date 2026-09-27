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
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
    #[error(transparent)]
    Target(#[from] target::Error),
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
        #[source]
        source: Option<packetcraftr_core::template::Error>,
    },
    #[error("could not materialize {field} on layer {layer}: {message}")]
    PacketMaterialization {
        layer: usize,
        field: &'static str,
        message: String,
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

impl From<packetcraftr_core::template::Error> for Error {
    fn from(source: packetcraftr_core::template::Error) -> Self {
        Self::Template {
            message: "the template could not be expanded".to_owned(),
            source: Some(source),
        }
    }
}
