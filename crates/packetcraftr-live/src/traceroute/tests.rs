// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use packetcraftr_packet::error::{Classification, Classified, Kind};
use packetcraftr_packet::protocol::builtin::registry;

use crate::BoundaryError;
use crate::clock::Clock;
use crate::target::{Authorized, Authorizer as TargetAuthorizer, Target};

use super::engine::traceroute;
use super::model::{
    TracerouteBatch, TracerouteBatchExecution, TracerouteExecutor, TracerouteLimits,
    TracerouteRequest, TracerouteStrategy,
};
use crate::target::Family;

fn request() -> TracerouteRequest {
    TracerouteRequest {
        target: Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
        strategy: TracerouteStrategy::Udp,
        address_family: Family::Any,
        destination_port: Some(super::DEFAULT_TRACEROUTE_UDP_PORT),
        first_hop: 1,
        max_hops: 1,
        probes_per_hop: 1,
        timeout: Duration::from_millis(1),
        probes_per_second: None,
        limits: TracerouteLimits::default(),
    }
}

struct FixtureAuthorizer;

impl TargetAuthorizer for FixtureAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        let Target::Address(address) = target else {
            unreachable!("fixture uses an address target")
        };
        Ok(Authorized {
            declared: target.clone(),
            addresses: vec![*address],
        })
    }

    fn authorize_operation(
        &mut self,
        _packets: u64,
        _maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct RejectExecutor;

impl TracerouteExecutor for RejectExecutor {
    fn execute(
        &mut self,
        _batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, BoundaryError> {
        Err(BoundaryError::new(
            "fixture stopped before forgeable evidence could be supplied",
            Classification::new("io.test", Kind::Io, None),
            Vec::new(),
        ))
    }
}

#[derive(Default)]
struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn traceroute_executor_is_reached_only_after_authorization() {
    let error = traceroute(
        &request(),
        &mut FixtureAuthorizer,
        &registry().expect("built-in registry"),
        &mut RejectExecutor,
        &mut NoopClock,
    )
    .expect_err("fixture executor rejects after authorization");
    assert_eq!(error.classification().code, "io.test");
}
