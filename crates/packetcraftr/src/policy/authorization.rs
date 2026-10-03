// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use crate::route::Plan;
use packetcraftr_core::{
    packet::MacAddress, packet::Packet, protocol::link::Ethernet, protocol::semantics,
};

use super::model::{Error, MAX_DESTINATION_CONSTRAINTS, MAX_RESOLVED_ADDRESSES, Policy};
use crate::address::is_public;
use crate::target::{
    Authorized, Error as TargetError, Hostname, Resolver, Target, distinct_addresses,
};

impl Policy {
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=MAX_RESOLVED_ADDRESSES).contains(&self.max_resolved_addresses) {
            return Err(Error::InvalidAddressLimit {
                value: self.max_resolved_addresses,
                maximum: MAX_RESOLVED_ADDRESSES,
            });
        }
        if self.allowed_destinations.len() > MAX_DESTINATION_CONSTRAINTS {
            return Err(Error::DestinationConstraintLimit {
                actual: self.allowed_destinations.len(),
                maximum: MAX_DESTINATION_CONSTRAINTS,
            });
        }
        Ok(())
    }

    pub fn authorize_destination(&self, destination: IpAddr) -> Result<(), Error> {
        if !self.allowed_destinations.is_empty()
            && !self
                .allowed_destinations
                .iter()
                .any(|constraint| constraint.contains(destination))
        {
            let constraints = self
                .allowed_destinations
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::DestinationNotAllowed {
                destination,
                constraints,
            });
        }
        if !self.allow_public_destinations && is_public(destination) {
            return Err(Error::PublicDestination { destination });
        }
        Ok(())
    }

    pub(super) fn authorize_wire_limits(&self, packets: u64, wire_bytes: u64) -> Result<(), Error> {
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

    pub(super) fn authorize_traffic_limits(
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

    pub fn authorize_packet_destinations(&self, packet: &Packet) -> Result<(), Error> {
        let destinations = semantics::live_destinations(packet).map_err(|source| {
            Error::InvalidPacketSemantics {
                reason: "its live destinations cannot be read".to_owned(),
                source: Some(source),
            }
        })?;
        for destination in destinations {
            self.authorize_destination(destination)?;
        }
        Ok(())
    }

    pub fn authorize_packet_sources(&self, packet: &Packet, plan: &Plan) -> Result<(), Error> {
        if self.allow_source_spoofing {
            return Ok(());
        }
        let decision = &plan.decision;
        let packet_source = semantics::outer_ip_path(packet)
            .map_err(|source| Error::InvalidPacketSemantics {
                reason: "its outer IP source cannot be read".to_owned(),
                source: Some(source),
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
            .find_map(|layer| layer.downcast_ref::<Ethernet>())
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
                distinct_addresses(
                    hostname,
                    resolver.resolve(hostname, self.max_resolved_addresses)?,
                    self.max_resolved_addresses,
                )?
            }
        };
        self.authorize_selected(target, addresses)
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::test_support::ScriptedResolver;

    fn address(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn resolve(answer: Vec<IpAddr>, limit: usize) -> Result<Authorized, TargetError> {
        let policy = Policy {
            allow_hostname_resolution: true,
            max_resolved_addresses: limit,
            ..Policy::default()
        };
        let target = Target::Hostname("example.test".parse().expect("hostname"));
        policy.resolve_target(&target, &ScriptedResolver::new([answer]))
    }

    #[test]
    fn rejected_resolver_answers_name_the_hostname() {
        let over_limit = resolve(vec![address(1), address(2), address(3)], 2)
            .expect_err("a third distinct address exceeds the limit");
        assert!(matches!(
            over_limit,
            TargetError::AddressLimit { ref hostname, limit: 2 } if hostname == "example.test"
        ));

        let empty = resolve(Vec::new(), 2).expect_err("an empty answer resolves nothing");
        assert!(matches!(
            empty,
            TargetError::NoAddresses { ref hostname } if hostname == "example.test"
        ));
    }
}
