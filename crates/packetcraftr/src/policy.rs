// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live traffic authorization policy.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use thiserror::Error;

use packetcraftr_core::error::{Classification, Classified};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{Packet, decode::Dissector, protocol::link::Ethernet, semantics};
use packetcraftr_netio::{link::MacAddress, route::Plan};

use crate::address::is_public;
use crate::target::{Authorized, Error as TargetError, Hostname, Resolver, Target};

pub const DEFAULT_MAX_RESOLVED_ADDRESSES: usize = 64;
pub const MAX_RESOLVED_ADDRESSES: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub allow_public_destinations: bool,
    /// Hostname resolution is a separate opt-in because a name has no stable
    /// address scope until after a resolver side effect.
    pub allow_hostname_resolution: bool,
    pub allow_permissive_packets: bool,
    /// Single opt-in for an explicit outer IP or Ethernet source the selected
    /// interface does not own. Replay transmits captured sources verbatim and
    /// does not consult it.
    pub allow_source_spoofing: bool,
    pub max_packets_per_operation: u64,
    pub max_bytes_per_operation: u64,
    pub max_resolved_addresses: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow_public_destinations: false,
            allow_hostname_resolution: false,
            allow_permissive_packets: false,
            allow_source_spoofing: false,
            max_packets_per_operation: 10_000,
            max_bytes_per_operation: 256 * 1024 * 1024,
            max_resolved_addresses: DEFAULT_MAX_RESOLVED_ADDRESSES,
        }
    }
}

impl Policy {
    /// Decodes and authorizes the exact bytes that will be placed on the wire.
    pub(crate) fn authorize_final_wire(
        &self,
        bytes: Vec<u8>,
        link_type: LinkType,
        plan: &Plan,
    ) -> Result<(), Error> {
        static REGISTRY: OnceLock<Result<Arc<Registry>, String>> = OnceLock::new();
        let registry = REGISTRY
            .get_or_init(|| {
                packetcraftr_core::protocol::builtin::registry()
                    .map(Arc::new)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|reason| Error::InvalidPacketSemantics {
                reason: reason.clone(),
            })?;
        self.authorize_link_type(link_type, registry, "final-wire")?;
        let frame =
            Frame::new(std::time::SystemTime::UNIX_EPOCH, link_type, bytes).map_err(|error| {
                Error::InvalidPacketSemantics {
                    reason: error.to_string(),
                }
            })?;
        let decoded = Dissector::new(Arc::clone(registry))
            .decode(frame, packetcraftr_core::decode::Options::default())
            .map_err(|error| Error::InvalidPacketSemantics {
                reason: error.to_string(),
            })?;
        self.authorize_packet_destinations(&decoded.packet)?;
        self.authorize_packet_sources(&decoded.packet, plan)
    }

    pub(crate) fn authorize_link_type(
        &self,
        link_type: LinkType,
        registry: &Registry,
        operation: &str,
    ) -> Result<(), Error> {
        if registry.root_for_link_type(link_type.0).is_none() {
            return Err(Error::InvalidPacketSemantics {
                reason: format!(
                    "{operation} authorization does not support link type {}",
                    link_type.0
                ),
            });
        }
        Ok(())
    }

    /// Validates policy configuration before resolver, route, capture, or
    /// transmission providers are invoked.
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=MAX_RESOLVED_ADDRESSES).contains(&self.max_resolved_addresses) {
            return Err(Error::InvalidAddressLimit {
                value: self.max_resolved_addresses,
                maximum: MAX_RESOLVED_ADDRESSES,
            });
        }
        Ok(())
    }

    /// Authorizes one already-resolved or packet-declared destination.
    pub fn authorize_destination(&self, destination: IpAddr) -> Result<(), Error> {
        if !self.allow_public_destinations && is_public(destination) {
            return Err(Error::PublicDestination { destination });
        }
        Ok(())
    }

    /// Applies the operation-wide packet and exact wire-byte budgets together.
    /// Callers provide prospective totals before starting live side effects.
    pub fn authorize_operation(&self, packets: u64, wire_bytes: u64) -> Result<(), Error> {
        if packets > self.max_packets_per_operation {
            return Err(Error::PacketLimit {
                actual: packets,
                limit: self.max_packets_per_operation,
            });
        }
        if wire_bytes > self.max_bytes_per_operation {
            return Err(Error::ByteLimit {
                actual: wire_bytes,
                limit: self.max_bytes_per_operation,
            });
        }
        Ok(())
    }

    /// Authorizes the explicit permissive-live opt-in and policy approval.
    pub fn authorize_permissive(
        &self,
        requires_live_opt_in: bool,
        allow_permissive_live: bool,
    ) -> Result<(), Error> {
        if requires_live_opt_in && !(allow_permissive_live && self.allow_permissive_packets) {
            return Err(Error::PermissiveLiveOptInRequired);
        }
        Ok(())
    }

    fn authorize_hostname(&self, hostname: &Hostname) -> Result<(), Error> {
        if !self.allow_hostname_resolution {
            return Err(Error::HostnameResolution {
                hostname: hostname.to_string(),
            });
        }
        Ok(())
    }

    /// Authorizes every route-bearing address declared by a packet before
    /// route, capture, neighbor, or transmission providers can observe it.
    pub fn authorize_packet_destinations(&self, packet: &Packet) -> Result<(), Error> {
        let destinations = semantics::live_destinations(packet).map_err(|source| {
            Error::InvalidPacketSemantics {
                reason: source.to_string(),
            }
        })?;
        for destination in destinations {
            self.authorize_destination(destination)?;
        }
        Ok(())
    }

    /// Authorizes the packet's outer IP and Ethernet sources against what the
    /// selected interface owns. Unspecified sources use planned values when available.
    pub fn authorize_packet_sources(&self, packet: &Packet, plan: &Plan) -> Result<(), Error> {
        if self.allow_source_spoofing {
            return Ok(());
        }
        let decision = &plan.decision;
        let packet_source = semantics::outer_ip_path(packet)
            .map_err(|source| Error::InvalidPacketSemantics {
                reason: source.to_string(),
            })?
            .map(|path| path.source)
            .map_or(plan.packet_source, |source| {
                if source.is_unspecified() {
                    plan.packet_source.or(Some(source))
                } else {
                    Some(source)
                }
            });
        let source_mac = semantics::outer_layers(packet)
            .find_map(|layer| layer.as_any().downcast_ref::<Ethernet>())
            .map(|ethernet| MacAddress(ethernet.source))
            .filter(|source| source.0 != [0; 6])
            .or(plan.source_mac);
        let foreign_ip = packet_source.filter(|source| {
            Some(*source) != decision.selected_source && Some(*source) != decision.preferred_source
        });
        let foreign_mac = source_mac.filter(|source| Some(*source) != decision.source_mac);
        let Some(packet_source) = foreign_ip
            .map(|source| source.to_string())
            .or_else(|| foreign_mac.map(|source| source.to_string()))
        else {
            return Ok(());
        };
        Err(Error::SourceNotInterfaceOwned {
            packet_source,
            interface: decision.interface.name.clone(),
        })
    }

    /// Authorizes a declared target before resolution, invokes the resolver at
    /// most once, then authorizes every selected address before returning any
    /// address to route planning. Calling this method again for re-resolution
    /// repeats both policy stages against the current policy.
    pub fn resolve_target<R: Resolver>(
        &self,
        target: &Target,
        resolver: &R,
    ) -> Result<Authorized, TargetError> {
        self.validate()?;
        let addresses = match target {
            Target::Address(address) => vec![*address],
            Target::Hostname(hostname) => {
                // This authorization must precede DNS, route lookup, capture,
                // neighbor discovery, and transmission side effects.
                self.authorize_hostname(hostname)?;
                let resolved = resolver.resolve(hostname, self.max_resolved_addresses)?;
                let mut addresses =
                    Vec::with_capacity(resolved.len().min(self.max_resolved_addresses));
                for address in resolved {
                    if addresses.contains(&address) {
                        continue;
                    }
                    if addresses.len() >= self.max_resolved_addresses {
                        return Err(TargetError::AddressLimit {
                            hostname: hostname.to_string(),
                            limit: self.max_resolved_addresses,
                        });
                    }
                    addresses.push(address);
                }
                if addresses.is_empty() {
                    return Err(TargetError::NoAddresses {
                        hostname: hostname.to_string(),
                    });
                }
                addresses
            }
        };
        for address in &addresses {
            self.authorize_destination(*address)?;
        }
        Ok(Authorized {
            declared: target.clone(),
            addresses,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("traffic policy denies public destination {destination}")]
    PublicDestination { destination: IpAddr },
    #[error("traffic policy cannot authorize packet routing semantics: {reason}")]
    InvalidPacketSemantics { reason: String },
    #[error("traffic policy denies hostname resolution for {hostname}")]
    HostnameResolution { hostname: String },
    #[error(
        "permissively built packets require both --allow-permissive-live and --allow-permissive-packets"
    )]
    PermissiveLiveOptInRequired,
    #[error("traffic policy denies source {packet_source} that interface {interface} does not own")]
    SourceNotInterfaceOwned {
        packet_source: String,
        interface: String,
    },
    #[error("operation packet count {actual} exceeds policy limit {limit}")]
    PacketLimit { actual: u64, limit: u64 },
    #[error("operation byte count {actual} exceeds policy limit {limit}")]
    ByteLimit { actual: u64, limit: u64 },
    #[error("resolved-address limit {value} is invalid; expected 1..={maximum}")]
    InvalidAddressLimit { value: usize, maximum: usize },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        let (code, remediation) = match self {
            Self::PublicDestination { .. } => (
                "policy.public_destination",
                "explicitly authorize public destinations only for networks you are permitted to test",
            ),
            Self::InvalidPacketSemantics { .. } => (
                "policy.invalid_packet_semantics",
                "repair malformed or unsupported route-bearing packet fields before live transmission",
            ),
            Self::HostnameResolution { .. } => (
                "policy.hostname_resolution",
                "explicitly authorize hostname resolution, then independently authorize every resolved address",
            ),
            Self::PermissiveLiveOptInRequired => (
                "policy.permissive_live_opt_in",
                "set the per-operation --allow-permissive-live opt-in and authorize permissive packets in the traffic policy",
            ),
            Self::SourceNotInterfaceOwned { .. } => (
                "policy.source_ownership",
                "use an interface-owned source, select it with the route source option, or explicitly authorize source spoofing",
            ),
            Self::PacketLimit { .. } => (
                "policy.packet_limit",
                "reduce the operation packet count or deliberately raise the configured traffic budget",
            ),
            Self::ByteLimit { .. } => (
                "policy.byte_limit",
                "reduce the operation byte count or deliberately raise the configured traffic budget",
            ),
            Self::InvalidAddressLimit { .. } => (
                "cli.policy_limit",
                "use a resolved-address limit between 1 and the documented maximum",
            ),
        };
        Classification::new(code, Some(remediation))
    }
}
