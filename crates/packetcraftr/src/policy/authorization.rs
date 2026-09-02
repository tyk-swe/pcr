// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::{Packet, packet::semantics, protocol::link::Ethernet};
use packetcraftr_netio::{link::MacAddress, route::Plan};

use super::contract::{Error, MAX_RESOLVED_ADDRESSES, Policy};
use crate::address::is_public;
use crate::target::{Authorized, Error as TargetError, Hostname, Resolver, Target};

impl Policy {
    /// Validates policy configuration before resolver, route, capture, or
    /// transmission providers are invoked.
    ///
    /// This is a pure policy check, so it is reachable from callers that never
    /// resolve a target at all — replay is one.
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
    ///
    /// Authorization seam used by the bounded workflows. Not part of the
    /// documented API.
    #[doc(hidden)]
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

    /// Applies the shared policy ceilings to DNS's explicit aggregate of raw
    /// packets and bounded socket connection/message traffic units.
    #[doc(hidden)]
    pub fn authorize_dns_operation(
        &self,
        traffic_units: u64,
        wire_and_application_bytes: u64,
    ) -> Result<(), Error> {
        if traffic_units > self.max_packets_per_operation {
            return Err(Error::TrafficUnitLimit {
                actual: traffic_units,
                limit: self.max_packets_per_operation,
            });
        }
        if wire_and_application_bytes > self.max_bytes_per_operation {
            return Err(Error::TrafficByteLimit {
                actual: wire_and_application_bytes,
                limit: self.max_bytes_per_operation,
            });
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
            .map_or(plan.source_mac, |source| {
                if source.0 == [0; 6] {
                    plan.source_mac.or(Some(source))
                } else {
                    Some(source)
                }
            });
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
    pub fn resolve_target<R: Resolver + ?Sized>(
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
        self.authorize_selected(target, addresses)
    }

    /// Authorizes a target that names its address outright, without a
    /// resolver. The destination stage is exactly the one
    /// [`Policy::resolve_target`] applies to a resolved answer.
    pub(crate) fn authorize_numeric_target(
        &self,
        target: &Target,
        address: IpAddr,
    ) -> Result<Authorized, TargetError> {
        self.validate()?;
        self.authorize_selected(target, vec![address])
    }

    fn authorize_selected(
        &self,
        target: &Target,
        addresses: Vec<IpAddr>,
    ) -> Result<Authorized, TargetError> {
        for address in &addresses {
            self.authorize_destination(*address)?;
        }
        Ok(Authorized {
            declared: target.clone(),
            addresses,
        })
    }
}
