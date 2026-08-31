// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Route-planning failures and their stable classifications.

use std::error::Error as StdError;
use std::net::IpAddr;

use thiserror::Error;

use packetcraftr_core::error::{Classification, Classified, Kind};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("route lookup for {destination} failed: {source}")]
    RouteLookup {
        destination: IpAddr,
        #[source]
        source: Box<dyn StdError + Send + Sync>,
        failure: Classification,
    },
    #[error("packet has no IP destination and none was supplied")]
    MissingDestination,
    #[error("destination-free Layer 2 planning requires an explicit interface")]
    MissingLayer2Interface,
    #[error("route provider cannot select interface {interface} without an IP destination")]
    InterfaceLookupUnsupported { interface: String },
    #[error("interface lookup for {interface} failed: {source}")]
    InterfaceLookup {
        interface: String,
        #[source]
        source: Box<dyn StdError + Send + Sync>,
        failure: Classification,
    },
    #[error(
        "route provider selected {selected} (index {selected_index}) instead of requested {requested} (index {requested_index})"
    )]
    InterfaceMismatch {
        requested: String,
        requested_index: u32,
        selected: String,
        selected_index: u32,
    },
    #[error("destination-free Layer 2 packet has no complete destination MAC address")]
    MissingLayer2DestinationMac,
    #[error("explicit Layer 3 mode cannot carry Ethernet or VLAN layers")]
    EthernetInLayer3,
    #[error("capture-only link header {protocol} cannot be used for live transmission")]
    OfflineOnlyLinkHeader {
        protocol: packetcraftr_core::layer::Id,
    },
    #[error("selected interface does not support Layer 2 transmission")]
    Layer2Unsupported,
    #[error("selected interface does not support Layer 3 transmission")]
    Layer3Unsupported,
    #[error("Layer 2 plan on {interface} has no interface-owned neighbor source address")]
    MissingNeighborSource { interface: String },
    #[error("Layer 2 plan on {interface} has no neighbor target")]
    MissingNeighborTarget { interface: String },
    #[error("interface {interface} has no source MAC for Layer 2 transmission")]
    MissingSourceMac { interface: String },
    /// Active neighbor resolution failed while materializing this route.
    ///
    /// Boxed because a neighbor failure carries the captured discovery
    /// evidence, which no other route failure should have to make room for.
    #[error(transparent)]
    Neighbor(Box<crate::neighbor::Error>),
    #[error("route source address family does not match destination {destination}")]
    SourceFamilyMismatch { destination: IpAddr },
    #[error(
        "preferred route source {preferred_source} has a different address family than destination {destination}"
    )]
    PreferredSourceFamilyMismatch {
        preferred_source: IpAddr,
        destination: IpAddr,
    },
    #[error("route provider did not select preferred source {requested}; selected {selected:?}")]
    PreferredSourceNotSelected {
        requested: IpAddr,
        selected: Option<IpAddr>,
    },
    #[error("route did not select a source address for the packet")]
    MissingPacketSource,
    #[error("invalid Segment Routing Header route state: {message}")]
    InvalidSegmentRouting { message: String },
    #[error("invalid IPv4 source-route state: {message}")]
    InvalidSourceRouting { message: String },
    #[error("packet carries an invalid neighbor-discovery VLAN stack: {message}")]
    InvalidNeighborVlan {
        message: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
}

impl From<crate::neighbor::Error> for Error {
    fn from(error: crate::neighbor::Error) -> Self {
        Self::Neighbor(Box::new(error))
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::RouteLookup { failure, .. } | Self::InterfaceLookup { failure, .. } => *failure,
            Self::MissingLayer2Interface => Classification::new(
                "cli.interface_required",
                Kind::Cli,
                Some("select an explicit interface for a destination-free Layer 2 packet"),
            ),
            Self::InterfaceLookupUnsupported { .. }
            | Self::Layer2Unsupported
            | Self::Layer3Unsupported => Classification::new(
                "capability.link_mode",
                Kind::Capability,
                Some(
                    "select a provider and interface that support the explicitly requested link mode",
                ),
            ),
            Self::OfflineOnlyLinkHeader { .. } => Classification::new(
                "packet.offline_link_header",
                Kind::Packet,
                Some("replace the capture-only header with a live Ethernet or raw-IP packet root"),
            ),
            Self::MissingDestination
            | Self::MissingLayer2DestinationMac
            | Self::EthernetInLayer3
            | Self::SourceFamilyMismatch { .. }
            | Self::PreferredSourceFamilyMismatch { .. }
            | Self::InvalidSegmentRouting { .. }
            | Self::InvalidSourceRouting { .. }
            | Self::InvalidNeighborVlan { .. } => Classification::new(
                "packet.plan",
                Kind::Packet,
                Some(
                    "correct the packet destination, address family, or link-layer intent before planning again",
                ),
            ),
            Self::Neighbor(error) => error.classification(),
            Self::InterfaceMismatch { .. }
            | Self::MissingNeighborSource { .. }
            | Self::MissingNeighborTarget { .. }
            | Self::MissingSourceMac { .. }
            | Self::PreferredSourceNotSelected { .. }
            | Self::MissingPacketSource => Classification::new(
                "internal.route_contract",
                Kind::Internal,
                Some(
                    "do not transmit with the inconsistent route result; inspect or replace the route provider",
                ),
            ),
        }
    }

    /// Walked from the retained `#[source]` chain rather than hand-written,
    /// except for the transparent neighbor variant, whose own `Display` is
    /// already this error's message and which therefore delegates.
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Neighbor(error) => error.causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}
