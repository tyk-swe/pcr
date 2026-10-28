// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use crate::route::Plan;
use packetcraftr_core::{
    packet::MacAddress, packet::Packet, protocol::link::Ethernet, protocol::semantics,
};

use super::ResolutionError;
use super::address::is_public;
use super::model::{Error, MAX_DESTINATION_CONSTRAINTS, MAX_RESOLVED_ADDRESSES, Policy};
use crate::target::{Authorized, Hostname, Resolver, Target, distinct_addresses};

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
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<Authorized, ResolutionError> {
        deadline
            .live_remaining()
            .map_err(packetcraftr_core::error::BoundaryError::from_error)
            .map_err(crate::target::Error::from)?;
        self.validate()?;
        let result = (|| {
            let selected = match target {
                Target::Address(address) => vec![crate::target::SelectedAddress::new(*address)],
                Target::ScopedAddress(scoped) => {
                    self.authorize_destination(scoped.address().into())?;
                    let interface = crate::target::valid_zone_interface(
                        scoped.zone(),
                        resolver.resolve_zone(scoped.zone(), deadline)?,
                    )?;
                    vec![crate::target::SelectedAddress {
                        address: scoped.address().into(),
                        scope: Some(crate::target::ResolvedZone {
                            zone: scoped.zone().clone(),
                            interface,
                        }),
                    }]
                }
                Target::Hostname(hostname) => {
                    // This authorization must precede DNS, route lookup, capture,
                    // neighbor discovery, and transmission side effects.
                    self.authorize_hostname(hostname)?;
                    distinct_addresses(
                        hostname,
                        resolver.resolve_controlled(
                            hostname,
                            self.max_resolved_addresses,
                            deadline,
                        )?,
                        self.max_resolved_addresses,
                    )?
                    .into_iter()
                    .map(crate::target::SelectedAddress::new)
                    .collect()
                }
            };
            self.authorize_selected(target, selected)
        })();
        deadline
            .live_remaining()
            .map_err(packetcraftr_core::error::BoundaryError::from_error)
            .map_err(crate::target::Error::from)?;
        result
    }

    fn authorize_selected(
        &self,
        target: &Target,
        selected: Vec<crate::target::SelectedAddress>,
    ) -> Result<Authorized, ResolutionError> {
        for record in &selected {
            self.authorize_destination(record.address)?;
            if crate::target::requires_scope(record.address) && record.scope.is_none() {
                return Err(crate::target::Error::MissingScope {
                    address: record.address,
                }
                .into());
            }
        }
        Ok(Authorized {
            declared: target.clone(),
            selected,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::net::IpAddr;
    use std::time::Duration;

    use packetcraftr_core::budget::Deadline;
    use packetcraftr_core::error::Classified;

    use super::Policy;
    use crate::policy::{Error as PolicyError, ResolutionError};
    use crate::target::{Error as TargetError, Hostname, Resolver, Target};

    #[test]
    fn resolution_policy_denial_preserves_classification_and_causes() {
        let policy = Policy::default();
        let target: Target = "example.test".parse().unwrap();
        let error = policy
            .resolve_target(
                &target,
                &crate::target::SystemResolver,
                &Deadline::new(Duration::from_secs(1)),
            )
            .expect_err("hostname resolution is denied");
        let ResolutionError::Policy(PolicyError::HostnameResolution { hostname }) = &error else {
            panic!("expected policy hostname denial, got {error:?}");
        };
        assert_eq!(hostname, "example.test");
        let expected = PolicyError::HostnameResolution {
            hostname: hostname.clone(),
        };
        assert_eq!(error.classification(), expected.classification());
        assert_eq!(error.causes(), expected.causes());
        assert!(error.source().is_none());
    }

    #[test]
    fn resolution_target_failure_preserves_classification_and_causes() {
        struct FailingResolver;
        impl Resolver for FailingResolver {
            fn resolve(&self, hostname: &Hostname, _: usize) -> Result<Vec<IpAddr>, TargetError> {
                Err(TargetError::Resolver {
                    hostname: hostname.to_string(),
                    source: std::io::Error::other("resolver unavailable").into(),
                })
            }
        }

        let policy = Policy {
            allow_hostname_resolution: true,
            ..Policy::default()
        };
        let target: Target = "example.test".parse().unwrap();
        let error = policy
            .resolve_target(
                &target,
                &FailingResolver,
                &Deadline::new(Duration::from_secs(1)),
            )
            .expect_err("resolver fails");
        let ResolutionError::Target(TargetError::Resolver { source, .. }) = &error else {
            panic!("expected target resolver failure, got {error:?}");
        };
        assert_eq!(source.to_string(), "resolver unavailable");
        assert_eq!(error.classification().code, "io.hostname_resolution");
        assert_eq!(
            error.classification().kind,
            packetcraftr_core::error::Kind::Io
        );
        assert_eq!(error.causes(), ["resolver unavailable"]);
        assert_eq!(
            error.source().map(ToString::to_string).as_deref(),
            Some("resolver unavailable")
        );
    }

    #[test]
    fn resolution_deadline_interruption_preserves_target_control() {
        let policy = Policy::default();
        let target: Target = "127.0.0.1".parse().unwrap();
        let error = policy
            .resolve_target(
                &target,
                &crate::target::SystemResolver,
                &Deadline::immediate(None),
            )
            .expect_err("immediate deadline interrupts resolution");
        let ResolutionError::Target(TargetError::Control(source)) = &error else {
            panic!("expected target deadline control, got {error:?}");
        };
        assert_eq!(error.classification(), source.classification());
        assert_eq!(error.causes(), source.causes());
        assert!(error.source().is_some());
    }

    #[test]
    fn numeric_and_custom_resolution_boundaries() {
        use std::sync::Arc;

        use packetcraftr_core::budget::Cancellation;

        struct Late(Cancellation);
        impl Resolver for Late {
            fn resolve(&self, _: &Hostname, _: usize) -> Result<Vec<IpAddr>, TargetError> {
                unreachable!()
            }

            fn resolve_controlled(
                &self,
                _: &Hostname,
                _: usize,
                _: &Deadline,
            ) -> Result<Vec<IpAddr>, TargetError> {
                self.0.cancel();
                Ok(vec!["127.0.0.1".parse().unwrap()])
            }
        }
        let policy = Policy {
            allow_hostname_resolution: true,
            ..Default::default()
        };
        let cancel = Cancellation::default();
        let resolver = Late(cancel.clone());
        assert!(matches!(
            policy.resolve_target(
                &"127.0.0.1".parse().unwrap(),
                &resolver,
                &Deadline::immediate(None)
            ),
            Err(ResolutionError::Target(TargetError::Control(_)))
        ));
        let parent = Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancel));
        let deadline = Deadline::new(Duration::from_secs(1)).with_parent(Some(Arc::new(parent)));
        assert!(matches!(
            policy.resolve_target(&"example.test".parse().unwrap(), &resolver, &deadline),
            Err(ResolutionError::Target(TargetError::Control(_)))
        ));
    }

    #[test]
    fn default_policy_denies_public_destinations_and_allowlist_never_grants_them() {
        let public_v4: IpAddr = "1.2.3.4".parse().unwrap();
        let public_v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        let policy = Policy::default();
        for denied in [public_v4, public_v6, "224.0.0.1".parse().unwrap()] {
            assert!(
                matches!(
                    policy.authorize_destination(denied),
                    Err(PolicyError::PublicDestination { .. })
                ),
                "{denied}"
            );
        }
        for allowed in ["127.0.0.1", "10.0.0.1", "::1"] {
            assert!(
                policy
                    .authorize_destination(allowed.parse().unwrap())
                    .is_ok(),
                "{allowed}"
            );
        }

        let allowlisted = Policy {
            allowed_destinations: vec!["1.2.3.4".parse().unwrap()],
            ..Policy::default()
        };
        assert!(matches!(
            allowlisted.authorize_destination(public_v4),
            Err(PolicyError::PublicDestination { .. })
        ));
        assert!(matches!(
            allowlisted.authorize_destination("127.0.0.1".parse().unwrap()),
            Err(PolicyError::DestinationNotAllowed { .. })
        ));

        let permissive = Policy {
            allow_public_destinations: true,
            ..Policy::default()
        };
        assert!(permissive.authorize_destination(public_v4).is_ok());
    }
}
