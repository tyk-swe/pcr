use std::net::IpAddr;

use crate::packet::{Packet, semantics};

use super::super::helpers::is_public;
use super::super::target::{
    Hostname, HostnameResolver, LiveTarget, ResolvedTarget, TargetResolutionError,
};
use super::contract::{MAX_RESOLVED_ADDRESSES, TrafficPolicy, TrafficPolicyError};

impl TrafficPolicy {
    /// Validates policy configuration before resolver, route, capture, or
    /// transmission providers are invoked.
    pub fn validate(&self) -> Result<(), TargetResolutionError> {
        if !(1..=MAX_RESOLVED_ADDRESSES).contains(&self.max_resolved_addresses) {
            return Err(TargetResolutionError::InvalidAddressLimit {
                value: self.max_resolved_addresses,
                maximum: MAX_RESOLVED_ADDRESSES,
            });
        }
        Ok(())
    }

    /// Authorizes one already-resolved or packet-declared destination.
    pub fn authorize_destination(&self, destination: IpAddr) -> Result<(), TrafficPolicyError> {
        if !self.allow_public_destinations && is_public(destination) {
            return Err(TrafficPolicyError::PublicDestination { destination });
        }
        Ok(())
    }

    /// Applies the operation-wide packet and exact wire-byte budgets together.
    /// Callers provide prospective totals before starting live side effects.
    pub(crate) fn authorize_operation(
        &self,
        packets: u64,
        wire_bytes: u64,
    ) -> Result<(), TrafficPolicyError> {
        if packets > self.max_packets_per_operation {
            return Err(TrafficPolicyError::PacketLimit {
                actual: packets,
                limit: self.max_packets_per_operation,
            });
        }
        if wire_bytes > self.max_bytes_per_operation {
            return Err(TrafficPolicyError::ByteLimit {
                actual: wire_bytes,
                limit: self.max_bytes_per_operation,
            });
        }
        Ok(())
    }

    fn authorize_hostname(&self, hostname: &Hostname) -> Result<(), TrafficPolicyError> {
        if !self.allow_hostname_resolution {
            return Err(TrafficPolicyError::HostnameResolution {
                hostname: hostname.to_string(),
            });
        }
        Ok(())
    }

    /// Authorizes every route-bearing address declared by a packet before
    /// route, capture, neighbor, or transmission providers can observe it.
    pub fn authorize_packet_destinations(&self, packet: &Packet) -> Result<(), TrafficPolicyError> {
        let destinations = semantics::live_destinations(packet).map_err(|source| {
            TrafficPolicyError::InvalidPacketSemantics {
                reason: source.to_string(),
            }
        })?;
        for destination in destinations {
            self.authorize_destination(destination)?;
        }
        Ok(())
    }

    /// Authorizes a declared target before resolution, invokes the resolver at
    /// most once, then authorizes every selected address before returning any
    /// address to route planning. Calling this method again for re-resolution
    /// repeats both policy stages against the current policy.
    pub fn resolve_target<R: HostnameResolver>(
        &self,
        target: &LiveTarget,
        resolver: &R,
    ) -> Result<ResolvedTarget, TargetResolutionError> {
        self.validate()?;
        let addresses = match target {
            LiveTarget::Address(address) => vec![*address],
            LiveTarget::Hostname(hostname) => {
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
                        return Err(TargetResolutionError::AddressLimit {
                            hostname: hostname.to_string(),
                            limit: self.max_resolved_addresses,
                        });
                    }
                    addresses.push(address);
                }
                if addresses.is_empty() {
                    return Err(TargetResolutionError::NoAddresses {
                        hostname: hostname.to_string(),
                    });
                }
                addresses
            }
        };
        for address in &addresses {
            self.authorize_destination(*address)?;
        }
        Ok(ResolvedTarget {
            declared: target.clone(),
            addresses,
        })
    }
}
