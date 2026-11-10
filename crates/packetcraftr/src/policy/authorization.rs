// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::protocol::identity;
use std::net::IpAddr;

use crate::route::Plan;
use packetcraftr_core::{packet::MacAddress, packet::Packet, protocol::semantics};

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
            .find_map(identity::link_addresses)
            .map(|(source, _)| MacAddress(source))
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
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use packetcraftr_core::budget::Deadline;
    use packetcraftr_core::error::{Classified, Kind};
    use packetcraftr_core::{
        build::{Builder, BuiltPacket, Options},
        codec::{Addresses, Mode as BuildMode},
        frame::LinkType,
        packet::{MacAddress, Packet},
        protocol::{link::Ethernet, network::Ipv4},
    };
    use packetcraftr_netio::{
        interface::Id,
        link::{Capability, Mode},
        route::{Decision, Scope, SelectionReason},
    };

    use super::Policy;
    use crate::policy::{
        DestinationConstraint, Error as PolicyError, MAX_DESTINATION_CONSTRAINTS,
        MAX_RESOLVED_ADDRESSES, ResolutionError,
    };
    use crate::route::Plan;
    use crate::target::{Error as TargetError, Hostname, Resolver, Target};

    fn source_plan() -> Plan {
        let source = "10.0.0.1".parse().unwrap();
        let mac = MacAddress([2, 0, 0, 0, 0, 1]);
        Plan {
            decision: Decision {
                interface: Id {
                    index: 1,
                    name: "test0".to_owned(),
                },
                source_mac: Some(mac),
                selected_source: Some(source),
                preferred_source: Some("10.0.0.2".parse().unwrap()),
                next_hop: None,
                selection_reason: SelectionReason::OnLink,
                destination_scope: Scope::Private,
                mtu: 1500,
                capability: Capability::Layer2AndLayer3,
                link_type: LinkType::ETHERNET,
            },
            mode: Mode::Layer2,
            lookup_destination: None,
            final_destination: None,
            visited_destinations: Vec::new(),
            packet_source: Some(source),
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: Some(mac),
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        }
    }

    fn source_packet(source: Ipv4Addr, mac: [u8; 6]) -> Packet {
        let mut packet = Packet::default();
        packet.push(Ethernet {
            source: mac,
            ..Ethernet::default()
        });
        packet.push(Ipv4 {
            source,
            destination: Ipv4Addr::LOCALHOST,
            ..Ipv4::default()
        });
        packet
    }

    fn build_packet(packet: Packet, mode: BuildMode) -> BuiltPacket {
        Builder::new(packetcraftr_core::protocol::builtin::registry())
            .build(
                packet,
                Addresses::default(),
                Options {
                    mode,
                    ..Options::default()
                },
            )
            .unwrap()
    }

    #[test]
    fn source_ownership_accepts_selected_preferred_and_planned_sources() {
        let plan = source_plan();
        let policy = Policy::default();
        for source in ["10.0.0.1", "10.0.0.2", "0.0.0.0"] {
            let packet = source_packet(source.parse().unwrap(), [2, 0, 0, 0, 0, 1]);
            assert!(
                policy.authorize_packet_sources(&packet, &plan).is_ok(),
                "{source}"
            );
        }
        let placeholder = source_packet(Ipv4Addr::UNSPECIFIED, [0; 6]);
        assert!(policy.authorize_packet_sources(&placeholder, &plan).is_ok());
        assert!(
            policy
                .authorize_packet_sources(&Packet::default(), &plan)
                .is_ok()
        );
    }

    #[test]
    fn foreign_packet_sources_require_explicit_spoofing_permission() {
        let plan = source_plan();
        let policy = Policy::default();
        for (ip, mac, denied) in [
            ("10.0.0.3", [2, 0, 0, 0, 0, 1], "10.0.0.3"),
            ("10.0.0.1", [2, 0, 0, 0, 0, 3], "02:00:00:00:00:03"),
        ] {
            let packet = source_packet(ip.parse().unwrap(), mac);
            assert!(matches!(policy.authorize_packet_sources(&packet, &plan),
                Err(PolicyError::SourceNotInterfaceOwned { packet_source, interface })
                    if packet_source == denied && interface == plan.decision.interface.name
            ));
            assert!(
                Policy {
                    allow_source_spoofing: true,
                    ..policy.clone()
                }
                .authorize_packet_sources(&packet, &plan)
                .is_ok()
            );
        }
    }

    #[test]
    fn permissive_packets_require_both_policy_and_operation_approval() {
        let packet = source_packet(Ipv4Addr::LOCALHOST, [2, 0, 0, 0, 0, 1]);
        let strict = build_packet(packet.clone(), BuildMode::Strict);
        assert!(
            Policy::default()
                .authorize_built_packet(&strict, false)
                .is_ok()
        );
        let permissive = build_packet(packet, BuildMode::Permissive);
        for (policy_allowed, operation_allowed) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let result = Policy {
                allow_permissive_packets: policy_allowed,
                ..Policy::default()
            }
            .authorize_built_packet(&permissive, operation_allowed);
            match (policy_allowed, operation_allowed) {
                (_, false) => assert!(matches!(result, Err(PolicyError::PermissiveLiveOptIn))),
                (false, true) => assert!(matches!(result, Err(PolicyError::PermissivePacket))),
                (true, true) => assert!(result.is_ok()),
            }
        }
    }

    #[test]
    fn wire_authorization_checks_the_encoded_source() {
        let plan = source_plan();
        for source in ["10.0.0.1", "10.0.0.3"] {
            let built = build_packet(
                source_packet(source.parse().unwrap(), [2, 0, 0, 0, 0, 1]),
                BuildMode::Strict,
            );
            let result = crate::policy::authorize_wire(
                &Policy::default(),
                LinkType::ETHERNET,
                &built.bytes,
                &plan,
            );
            if source == "10.0.0.1" {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result,
                    Err(PolicyError::SourceNotInterfaceOwned { packet_source, .. })
                        if packet_source == source
                ));
            }
        }
    }

    #[test]
    fn resolution_denial_preserves_error_details() {
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
        assert!(error.to_string().contains(hostname));
        let expected = PolicyError::HostnameResolution {
            hostname: hostname.clone(),
        };
        assert_eq!(error.classification(), expected.classification());
        assert_eq!(error.causes(), expected.causes());
        assert!(error.source().is_none());
    }

    #[test]
    fn resolution_failure_preserves_error_details() {
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
        assert_eq!(
            error.classification().code.as_str(),
            "io.hostname_resolution"
        );
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
    fn resolution_deadline_preserves_target_control() {
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
    fn allowlisting_cannot_grant_public_destinations() {
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

    #[test]
    fn destination_scope_handles_address_families_and_documentation_boundaries() {
        let policy = Policy::default();
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "127.0.0.1",
            "169.254.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "::",
            "::1",
            "fc00::1",
            "fdff::1",
            "fe80::1",
            "febf::1",
            "2001:db8::1",
            "3fff::1",
            "3fff:fff:ffff::1",
        ] {
            let address: IpAddr = address.parse().unwrap();
            assert!(policy.authorize_destination(address).is_ok(), "{address}");
            if let IpAddr::V4(ipv4) = address {
                assert!(
                    policy
                        .authorize_destination(ipv4.to_ipv6_mapped().into())
                        .is_ok(),
                    "mapped {address}"
                );
            }
        }
        for address in [
            "1.2.3.4",
            "224.0.0.1",
            "255.255.255.255",
            "2001:db7::1",
            "2001:db9::1",
            "2002:db8::1",
            "3ffe::1",
            "3fff:1000::1",
            "4000::1",
            "ff02::1",
            "fec0::1",
        ] {
            let address: IpAddr = address.parse().unwrap();
            assert!(
                matches!(
                    policy.authorize_destination(address),
                    Err(PolicyError::PublicDestination { destination }) if destination == address
                ),
                "{address}"
            );
            if let IpAddr::V4(ipv4) = address {
                assert!(
                    matches!(
                        policy.authorize_destination(ipv4.to_ipv6_mapped().into()),
                        Err(PolicyError::PublicDestination { .. })
                    ),
                    "mapped {address}"
                );
            }
        }
    }

    #[test]
    fn policy_validation_accepts_exact_limits_and_rejects_overflow() {
        for value in [1, MAX_RESOLVED_ADDRESSES] {
            assert!(
                Policy {
                    max_resolved_addresses: value,
                    ..Policy::default()
                }
                .validate()
                .is_ok()
            );
        }
        for value in [0, MAX_RESOLVED_ADDRESSES + 1] {
            let error = Policy {
                max_resolved_addresses: value,
                ..Policy::default()
            }
            .validate()
            .unwrap_err();
            assert_eq!(error.classification().kind, Kind::Usage);
            assert!(matches!(
                error,
                PolicyError::InvalidAddressLimit { value: actual, maximum }
                    if actual == value && maximum == MAX_RESOLVED_ADDRESSES
            ));
        }
        let constraint = "127.0.0.1".parse().unwrap();
        for count in [
            0,
            MAX_DESTINATION_CONSTRAINTS,
            MAX_DESTINATION_CONSTRAINTS + 1,
        ] {
            let policy = Policy {
                allowed_destinations: vec![constraint; count],
                ..Policy::default()
            };
            if count <= MAX_DESTINATION_CONSTRAINTS {
                assert!(policy.validate().is_ok());
            } else {
                assert!(matches!(policy.validate(),
                    Err(PolicyError::DestinationConstraintLimit { actual, maximum })
                        if actual == count && maximum == MAX_DESTINATION_CONSTRAINTS
                ));
            }
        }
    }

    #[test]
    fn allowlist_matches_exact_mapped_and_network_addresses() {
        let entries = [
            "10.0.0.1",
            "::ffff:10.0.0.2",
            "192.0.2.0/24",
            "2001:db8::/32",
        ];
        let policy = Policy {
            allowed_destinations: entries.map(|entry| entry.parse().unwrap()).into(),
            ..Policy::default()
        };
        for address in [
            "10.0.0.1",
            "::ffff:10.0.0.1",
            "10.0.0.2",
            "::ffff:10.0.0.2",
            "192.0.2.255",
            "2001:db8:ffff::1",
        ] {
            assert!(
                policy
                    .authorize_destination(address.parse().unwrap())
                    .is_ok(),
                "{address}"
            );
        }
        let destination = "10.0.0.3".parse().unwrap();
        let error = policy.authorize_destination(destination).unwrap_err();
        assert!(matches!(&error,
            PolicyError::DestinationNotAllowed { destination: actual, .. }
                if *actual == destination
        ));
        assert!(error.to_string().contains(&destination.to_string()));
        for entry in entries {
            assert!(
                error.to_string().contains(entry),
                "missing constraint {entry}"
            );
        }
    }

    #[test]
    fn invalid_destination_constraints_report_the_input_as_a_usage_error() {
        for input in [
            "invalid",
            "invalid/24",
            "10.0.0.0/33",
            "10.0.0.1/24",
            "2001:db8::1/32",
        ] {
            let error = input.parse::<DestinationConstraint>().unwrap_err();
            assert_eq!(error.classification().kind, Kind::Usage);
            assert!(matches!(error,
                PolicyError::InvalidDestinationConstraint { value, reason }
                    if value == input && !reason.is_empty()
            ));
        }
    }
}
