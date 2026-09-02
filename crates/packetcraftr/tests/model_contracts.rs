// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{
    Client, Stats, exchange, policy,
    target::{Error as TargetError, Family, Hostname, Resolver, Target},
};
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_netio as net;
use packetcraftr_netio::{
    Error as LiveIoError,
    capture::Statistics,
    interface::Id as InterfaceId,
    neighbor,
    route::{Decision, Provider},
    transmit,
};

struct FixedResolver(Vec<IpAddr>);

impl Resolver for FixedResolver {
    fn resolve(&self, _hostname: &Hostname, _limit: usize) -> Result<Vec<IpAddr>, TargetError> {
        Ok(self.0.clone())
    }
}

struct NoRoutes;

impl Provider for NoRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error> {
        unreachable!("registry accessor test never plans")
    }
}

struct NoNeighbors;

impl neighbor::Resolver for NoNeighbors {
    fn resolve(
        &self,
        _request: &neighbor::Request,
    ) -> Result<neighbor::Resolution, neighbor::Error> {
        unreachable!("registry accessor test never resolves neighbors")
    }
}

struct NoIo;

impl transmit::Sender for NoIo {
    fn send(&self, _frame: transmit::Frame<'_>) -> Result<transmit::Report, LiveIoError> {
        unreachable!("registry accessor test never transmits")
    }
}

#[test]
fn hostname_parser_canonicalizes_ascii_and_rejects_each_invalid_shape() {
    let hostname = Hostname::from_str("WWW.Example.COM.").expect("valid hostname");
    assert_eq!(hostname.as_str(), "www.example.com");
    assert_eq!(hostname.to_string(), "www.example.com");

    let long_label = format!("{}.test", "a".repeat(64));
    let long_name = format!("{}.com", "a".repeat(250));
    for invalid in [
        "".to_owned(),
        ".".to_owned(),
        "éxample.test".to_owned(),
        "bad..test".to_owned(),
        "-bad.test".to_owned(),
        "bad-.test".to_owned(),
        "bad_name.test".to_owned(),
        long_label,
        long_name,
    ] {
        assert!(matches!(
            Hostname::from_str(&invalid),
            Err(TargetError::InvalidHostname { .. })
        ));
    }
}

#[test]
fn target_parser_distinguishes_addresses_and_hostnames() {
    assert_eq!(
        Target::from_str("192.0.2.1").expect("IPv4 target"),
        Target::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    );
    assert_eq!(
        Target::from_str("2001:db8::1").expect("IPv6 target"),
        Target::Address(IpAddr::V6("2001:db8::1".parse().expect("IPv6")))
    );
    assert!(matches!(
        Target::from_str("Example.TEST").expect("hostname target"),
        Target::Hostname(hostname) if hostname.as_str() == "example.test"
    ));
    assert!(Target::from_str("not a host").is_err());
    assert_eq!(Family::Ipv4.label(), "IPv4");
    assert_eq!(Family::Ipv6.label(), "IPv6");
}

#[test]
fn target_serde_preserves_the_tagged_wire_contract() {
    let hostname = Target::from_str("Example.TEST.").expect("hostname target");
    let encoded = serde_json::to_string(&hostname).expect("serialize target");
    assert_eq!(encoded, r#"{"kind":"hostname","value":"example.test"}"#);
    assert_eq!(
        serde_json::from_str::<Target>(&encoded).expect("deserialize target"),
        hostname
    );

    let address = Target::from_str("192.0.2.1").expect("address target");
    assert_eq!(
        serde_json::to_string(&address).expect("serialize address target"),
        r#"{"kind":"address","value":"192.0.2.1"}"#
    );
}

#[test]
fn resolved_target_selects_first_and_family_specific_addresses() {
    let target = Target::from_str("example.test").expect("hostname");
    let resolver = FixedResolver(vec![
        IpAddr::V6("fd00::2".parse().expect("IPv6")),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
    ]);
    let resolved = policy::Policy {
        allow_hostname_resolution: true,
        ..policy::Policy::default()
    }
    .resolve_target(&target, &resolver)
    .expect("private resolved addresses");

    assert_eq!(resolved.declared(), &target);
    assert_eq!(resolved.selected_address(), resolver.0[0]);
    assert_eq!(
        resolved.address_for_family(Family::Ipv4),
        Some(resolver.0[1])
    );
    assert_eq!(
        resolved.address_for_family(Family::Ipv6),
        Some(resolver.0[0])
    );
}

#[test]
fn policy_classifies_private_special_public_and_mapped_addresses() {
    let policy = policy::Policy::default();
    for allowed in [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6("fd00::1".parse().expect("ULA")),
        IpAddr::V6("fe80::1".parse().expect("link local")),
        IpAddr::V6("2001:db8::1".parse().expect("documentation")),
        IpAddr::V6("::ffff:10.0.0.1".parse().expect("mapped private")),
    ] {
        policy
            .authorize_destination(allowed)
            .unwrap_or_else(|error| panic!("{allowed} must be allowed: {error}"));
    }

    for denied in [
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        IpAddr::V6("2606:4700:4700::1111".parse().expect("public IPv6")),
        IpAddr::V6("ff02::1".parse().expect("IPv6 multicast")),
        IpAddr::V6("::ffff:8.8.8.8".parse().expect("mapped public")),
    ] {
        assert!(matches!(
            policy.authorize_destination(denied),
            Err(policy::Error::PublicDestination { destination }) if destination == denied
        ));
    }

    policy::Policy {
        allow_public_destinations: true,
        ..policy
    }
    .authorize_destination(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
    .expect("explicit public policy opt-in");
}

#[test]
fn policy_validates_address_and_operation_bounds() {
    let defaults = policy::Policy::default();
    assert!(defaults.validate().is_ok());
    assert!(matches!(
        policy::Policy {
            max_resolved_addresses: 0,
            ..defaults.clone()
        }
        .validate(),
        Err(policy::Error::InvalidAddressLimit { value: 0, .. })
    ));
    let over_limit = policy::Policy {
        max_resolved_addresses: policy::MAX_RESOLVED_ADDRESSES + 1,
        ..defaults.clone()
    }
    .validate()
    .expect_err("an out-of-range resolved-address bound is rejected");
    assert!(matches!(
        over_limit,
        policy::Error::InvalidAddressLimit { .. }
    ));
    // The published CLI contract for this refusal does not move with its home.
    assert_eq!(over_limit.classification().code, "cli.live_target");
    assert_eq!(over_limit.classification().kind, Kind::Cli);
    assert_eq!(
        over_limit.to_string(),
        format!(
            "resolved-address limit {} is invalid; expected 1..={}",
            policy::MAX_RESOLVED_ADDRESSES + 1,
            policy::MAX_RESOLVED_ADDRESSES
        )
    );

    defaults
        .authorize_operation(
            defaults.max_packets_per_operation,
            defaults.max_bytes_per_operation,
        )
        .expect("limits are inclusive");
    assert!(matches!(
        defaults.authorize_operation(defaults.max_packets_per_operation + 1, 0),
        Err(policy::Error::PacketLimit { .. })
    ));
    assert!(matches!(
        defaults.authorize_operation(0, defaults.max_bytes_per_operation + 1),
        Err(policy::Error::ByteLimit { .. })
    ));
    defaults
        .authorize_dns_operation(
            defaults.max_packets_per_operation,
            defaults.max_bytes_per_operation,
        )
        .expect("DNS traffic-unit limits are inclusive");
    assert!(matches!(
        defaults.authorize_dns_operation(defaults.max_packets_per_operation + 1, 0),
        Err(policy::Error::TrafficUnitLimit { .. })
    ));
    assert!(matches!(
        defaults.authorize_dns_operation(0, defaults.max_bytes_per_operation + 1),
        Err(policy::Error::TrafficByteLimit { .. })
    ));
}

#[test]
fn resolution_rejects_empty_and_over_limit_results() {
    let target = Target::from_str("example.test").expect("hostname");
    let policy = policy::Policy {
        allow_hostname_resolution: true,
        max_resolved_addresses: 2,
        ..policy::Policy::default()
    };
    assert!(matches!(
        policy.resolve_target(&target, &FixedResolver(Vec::new())),
        Err(TargetError::NoAddresses { .. })
    ));
    assert!(matches!(
        policy.resolve_target(
            &target,
            &FixedResolver(vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            ])
        ),
        Err(TargetError::AddressLimit { limit: 2, .. })
    ));
}

#[test]
fn exchange_options_validate_all_aggregate_bounds() {
    let defaults = exchange::Options::default();
    defaults.validate().expect("default exchange options");
    // The single capture field is exactly what arms the provider, so the
    // aggregate ceilings and the snapshot length cannot drift from each other.
    assert_eq!(defaults.capture, net::capture::Limits::default());
    defaults
        .capture
        .validate()
        .expect("default exchange options imply valid capture limits");

    let invalid = [
        exchange::Options {
            timeout: exchange::MAX_EXCHANGE_TIMEOUT + Duration::from_nanos(1),
            ..defaults.clone()
        },
        exchange::Options {
            max_template_packets: 0,
            ..defaults.clone()
        },
        exchange::Options {
            max_responses: defaults.capture.max_frames + 1,
            ..defaults.clone()
        },
        exchange::Options {
            max_unmatched_frames: defaults.capture.max_frames + 1,
            ..defaults.clone()
        },
        exchange::Options {
            capture: net::capture::Limits {
                max_frames: 0,
                ..defaults.capture
            },
            max_responses: 0,
            max_unmatched_frames: 0,
            ..defaults.clone()
        },
        exchange::Options {
            capture: net::capture::Limits {
                max_bytes: 1,
                ..defaults.capture
            },
            ..defaults
        },
    ];
    for options in invalid {
        assert!(options.validate().is_err());
    }
}

#[test]
fn stats_checked_add_is_complete_and_atomic_on_overflow() {
    let mut total = Stats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 10,
        elapsed: Duration::from_secs(1),
        capture: Statistics {
            received_frames: 1,
            received_bytes: 5,
            dropped_frames: 1,
            dropped_bytes: 2,
            overflow_events: 1,
            receiver_dropped_frames: 1,
        },
    };
    let increment = total.clone();
    assert_eq!(total.checked_add_assign(&increment), Some(()));
    assert_eq!(total.packets_attempted, 2);
    assert_eq!(total.packets_completed, 2);
    assert_eq!(total.bytes, 20);
    assert_eq!(total.elapsed, Duration::from_secs(2));
    assert_eq!(total.capture.received_frames, 2);
    assert_eq!(total.capture.receiver_dropped_frames, 2);

    let before = total.clone();
    let overflow = Stats {
        bytes: u64::MAX,
        ..Stats::default()
    };
    assert_eq!(total.checked_add_assign(&overflow), None);
    assert_eq!(total, before);

    let overflow = Stats {
        capture: Statistics {
            receiver_dropped_frames: u64::MAX,
            ..Statistics::default()
        },
        ..Stats::default()
    };
    assert_eq!(total.checked_add_assign(&overflow), None);
    assert_eq!(total, before);

    let mut elapsed = Stats {
        elapsed: Duration::MAX,
        ..Stats::default()
    };
    let before = elapsed.clone();
    assert_eq!(
        elapsed.checked_add_assign(&Stats {
            elapsed: Duration::from_nanos(1),
            ..Stats::default()
        }),
        None
    );
    assert_eq!(elapsed, before);
}

#[test]
fn public_errors_retain_stable_policy_and_target_classification() {
    let cases: Vec<(Box<dyn Classified>, &str, Kind)> = vec![
        (
            Box::new(policy::Error::PermissivePacket),
            "policy.permissive_packet",
            Kind::Policy,
        ),
        (
            Box::new(policy::Error::InvalidPacketSemantics {
                reason: "fixture".to_owned(),
            }),
            "policy.invalid_packet_semantics",
            Kind::Policy,
        ),
        (
            Box::new(TargetError::AddressFamilyUnavailable { family: "IPv6" }),
            "packet.target_address_family",
            Kind::Packet,
        ),
        (
            Box::new(TargetError::InvalidHostname {
                hostname: "bad".to_owned(),
                reason: "fixture",
            }),
            "cli.live_target",
            Kind::Cli,
        ),
        (
            Box::new(TargetError::Resolver {
                hostname: "example.test".to_owned(),
                source: Box::new(io::Error::other("fixture")),
            }),
            "io.hostname_resolution",
            Kind::Io,
        ),
    ];

    for (error, code, kind) in cases {
        let classification = error.classification();
        assert_eq!(classification.code, code);
        assert_eq!(classification.kind, kind);
    }
}

/// A workflow failure publishes the causes of whatever it wraps, so a chain
/// that starts in another crate still reaches the render boundary intact: a
/// transparent variant delegates to the error it restates, and a variant with
/// a retained source walks it.
#[test]
fn workflow_failures_publish_the_causes_of_the_error_they_carry() {
    let udp = packetcraftr::core::layer::Id::from("udp");
    let codec = packetcraftr::core::build::Error::Codec {
        index: 1,
        protocol: udp,
        source: packetcraftr::core::codec::Error::Invalid {
            protocol: udp,
            message: "port 53 is reserved".to_owned(),
        },
    };
    let build_causes = codec.causes();
    assert_eq!(build_causes, ["invalid udp layer: port 53 is reserved"]);

    let workflow = packetcraftr::Error::Build(codec);
    assert_eq!(workflow.causes(), build_causes);

    // A hostname lookup keeps the system refusal instead of pasting it into
    // the message, so the message and the cause each say it once.
    let resolver = TargetError::Resolver {
        hostname: "example.test".to_owned(),
        source: Box::new(io::Error::other("name or service not known")),
    };
    assert_eq!(
        resolver.to_string(),
        "hostname resolution for example.test failed"
    );
    assert_eq!(resolver.causes(), ["name or service not known"]);
    assert_eq!(
        packetcraftr::Error::Target(resolver).causes(),
        ["name or service not known"]
    );
}

#[test]
fn client_exposes_the_exact_registry_arc() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let client = Client::new(
        Arc::clone(&registry),
        NoRoutes,
        NoNeighbors,
        NoIo,
        policy::Policy::default(),
    );
    assert!(Arc::ptr_eq(client.registry(), &registry));
}
