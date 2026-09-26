// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Offline-analysis vocabulary several commands publish: capture scopes,
//! the capture clock, stream identities, and endpoints.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::analysis::{self as library, reassembly::tcp, scope};

use super::contract::Error;

/// One semantic identifier in the ordered encapsulation path enclosing a flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind")]
pub enum EncapsulationIdentifier {
    #[serde(rename = "vlan")]
    Vlan { vlan_id: u16 },
    #[serde(rename = "vlan8021ad")]
    Vlan8021ad { vlan_id: u16 },
    #[serde(rename = "network")]
    Network { first: IpAddr, second: IpAddr },
    #[serde(rename = "vxlan")]
    Vxlan { vni: u32 },
    #[serde(rename = "geneve")]
    Geneve { vni: u32 },
    #[serde(rename = "gre")]
    Gre { key: Option<u32> },
    #[serde(rename = "mpls")]
    Mpls { label: u32 },
    #[serde(rename = "pppoe")]
    Pppoe {
        session_id: u16,
        endpoints: Option<([u8; 6], [u8; 6])>,
    },
    #[serde(rename = "l2tpv3")]
    L2tpv3 { session_id: u32 },
    #[serde(rename = "erspan")]
    Erspan { vlan: u16, session_id: u16 },
    #[serde(rename = "ah")]
    Ah { spi: u32 },
}

impl TryFrom<scope::EncapsulationIdentifier> for EncapsulationIdentifier {
    type Error = Error;

    fn try_from(value: scope::EncapsulationIdentifier) -> Result<Self, Error> {
        use scope::EncapsulationIdentifier as Library;
        Ok(match value {
            Library::Vlan { vlan_id } => Self::Vlan { vlan_id },
            Library::Vlan8021ad { vlan_id } => Self::Vlan8021ad { vlan_id },
            Library::Network { first, second } => Self::Network { first, second },
            Library::Vxlan { vni } => Self::Vxlan { vni },
            Library::Geneve { vni } => Self::Geneve { vni },
            Library::Gre { key } => Self::Gre { key },
            Library::Mpls { label } => Self::Mpls { label },
            Library::Pppoe {
                session_id,
                endpoints,
            } => Self::Pppoe {
                session_id,
                endpoints,
            },
            Library::L2tpv3 { session_id } => Self::L2tpv3 { session_id },
            Library::Erspan { vlan, session_id } => Self::Erspan { vlan, session_id },
            Library::Ah { spi } => Self::Ah { spi },
            _ => {
                return Err(Error::Unpublished {
                    value: "capture scope encapsulation",
                });
            }
        })
    }
}

/// An interpretable capture domain: a run-local scope identity, the
/// capture-global interface, and the enclosing encapsulation path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Scope {
    pub id: u32,
    pub interface: Option<u32>,
    pub encapsulation: Vec<EncapsulationIdentifier>,
}

impl TryFrom<scope::Definition> for Scope {
    type Error = Error;

    fn try_from(value: scope::Definition) -> Result<Self, Error> {
        Ok(Self {
            id: value.id.get(),
            interface: value.interface,
            encapsulation: value
                .encapsulation
                .iter()
                .copied()
                .map(EncapsulationIdentifier::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<&scope::Definition> for Scope {
    type Error = Error;

    fn try_from(value: &scope::Definition) -> Result<Self, Error> {
        value.clone().try_into()
    }
}

/// Capture-clock irregularities an analysis observed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Clock {
    pub regressions: u64,
    pub max_regression: Duration,
    pub max_forward_step: Duration,
    pub max_forward_step_frame: Option<u64>,
}

impl From<library::ClockReport> for Clock {
    fn from(value: library::ClockReport) -> Self {
        Self {
            regressions: value.regressions,
            max_regression: value.max_regression,
            max_forward_step: value.max_forward_step,
            max_forward_step_frame: value.max_forward_step_frame,
        }
    }
}

published_enum! {
    /// The transport a conversation index counts.
    pub enum StreamTransport from library::StreamTransport {
        Tcp => "tcp",
        Udp => "udp",
    }
}

/// One conversation, as `tcp.stream`/`udp.stream` index it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct StreamRef {
    pub transport: StreamTransport,
    pub index: u64,
}

impl From<library::StreamRef> for StreamRef {
    fn from(value: library::StreamRef) -> Self {
        Self {
            transport: value.transport.into(),
            index: value.index,
        }
    }
}

/// One side of a conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

/// `address:port`, bracketing an IPv6 address.
impl std::fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::net::SocketAddr::new(self.address, self.port).fmt(formatter)
    }
}

impl From<library::Endpoint> for Endpoint {
    fn from(value: library::Endpoint) -> Self {
        Self {
            address: value.address,
            port: value.port,
        }
    }
}

/// One direction of a transport flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlowKey {
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}

impl From<tcp::FlowKey> for FlowKey {
    fn from(value: tcp::FlowKey) -> Self {
        Self {
            source: value.source,
            source_port: value.source_port,
            destination: value.destination,
            destination_port: value.destination_port,
        }
    }
}

/// One direction of a transport flow within its capture scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScopedFlowKey {
    pub scope: u32,
    pub flow: FlowKey,
}

impl From<tcp::ScopedFlowKey> for ScopedFlowKey {
    fn from(value: tcp::ScopedFlowKey) -> Self {
        Self {
            scope: value.scope.get(),
            flow: value.flow.into(),
        }
    }
}
