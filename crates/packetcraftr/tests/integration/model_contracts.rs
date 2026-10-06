// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;

use packetcraftr::{
    policy,
    target::{Error as TargetError, Hostname, Resolver, Target},
};
use packetcraftr_core::error::{Classified, Kind};

const LIVE: Duration = Duration::from_secs(30);

struct FixedResolver(Vec<IpAddr>);

impl Resolver for FixedResolver {
    fn resolve(&self, _hostname: &Hostname, _limit: usize) -> Result<Vec<IpAddr>, TargetError> {
        Ok(self.0.clone())
    }
}

#[test]
fn host_parser_reject_invalid_shape() {
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
fn policy_validates_address_operation_bounds() {
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
    assert_eq!(over_limit.classification().kind, Kind::Usage);
    assert_eq!(
        over_limit.classification().remediation,
        Some("set the resolved-address limit to at least 1 and no more than the supported maximum")
    );
    let too_many_constraints = policy::Policy {
        allowed_destinations: vec![
            "192.0.2.1".parse().expect("constraint");
            policy::MAX_DESTINATION_CONSTRAINTS + 1
        ],
        ..defaults.clone()
    }
    .validate()
    .expect_err("a constraint list beyond its bound is rejected");
    assert!(matches!(
        too_many_constraints,
        policy::Error::DestinationConstraintLimit { .. }
    ));
    assert_eq!(
        too_many_constraints.classification().remediation,
        Some(
            "declare fewer destination constraints, covering adjacent hosts with one CIDR network where possible"
        )
    );

    defaults
        .authorize(policy::Operation::Wire(policy::WireLimits::new(
            defaults.max_packets_per_operation,
            defaults.max_bytes_per_operation,
        )))
        .expect("limits are inclusive");
    assert!(matches!(
        defaults.authorize(policy::Operation::Wire(policy::WireLimits::new(
            defaults.max_packets_per_operation + 1,
            0
        ))),
        Err(policy::Error::PacketLimit { .. })
    ));
    assert!(matches!(
        defaults.authorize(policy::Operation::Wire(policy::WireLimits::new(
            0,
            defaults.max_bytes_per_operation + 1
        ))),
        Err(policy::Error::ByteLimit { .. })
    ));
    defaults
        .authorize(policy::Operation::Dns(
            policy::DnsOperation::new(
                policy::WireLimits::new(
                    defaults.max_packets_per_operation,
                    defaults.max_bytes_per_operation,
                ),
                policy::SocketLimits::none(),
            )
            .unwrap(),
        ))
        .expect("DNS traffic-unit limits are inclusive");
    assert!(matches!(
        defaults.authorize(policy::Operation::Dns(
            policy::DnsOperation::new(
                policy::WireLimits::new(defaults.max_packets_per_operation + 1, 0),
                policy::SocketLimits::none()
            )
            .unwrap()
        )),
        Err(policy::Error::TrafficUnitLimit { .. })
    ));
    assert!(matches!(
        defaults.authorize(policy::Operation::Dns(
            policy::DnsOperation::new(
                policy::WireLimits::new(0, defaults.max_bytes_per_operation + 1),
                policy::SocketLimits::none()
            )
            .unwrap()
        )),
        Err(policy::Error::TrafficByteLimit { .. })
    ));
}

#[test]
fn resolution_reject_empty_limit_results() {
    let target = Target::from_str("example.test").expect("hostname");
    let policy = policy::Policy {
        allow_hostname_resolution: true,
        max_resolved_addresses: 2,
        ..policy::Policy::default()
    };
    assert!(matches!(
        policy.resolve_target(&target, &FixedResolver(Vec::new()), &Deadline::new(LIVE)),
        Err(TargetError::NoAddresses { .. })
    ));
    assert!(matches!(
        policy.resolve_target(
            &target,
            &FixedResolver(vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            ]),
            &Deadline::new(LIVE),
        ),
        Err(TargetError::AddressLimit { limit: 2, .. })
    ));
}
