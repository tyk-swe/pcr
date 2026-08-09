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

use super::engine::scan;
use super::model::{
    ScanBatch, ScanBatchExecution, ScanExecutor, ScanLimits, ScanRequest, ScanTransport,
};
use crate::target::Family;

fn request() -> ScanRequest {
    ScanRequest {
        target: Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        transport: ScanTransport::Tcp,
        address_family: Family::Any,
        ports: vec![80],
        attempts: 1,
        timeout: Duration::from_millis(1),
        probes_per_second: None,
        limits: ScanLimits::default(),
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

impl ScanExecutor for RejectExecutor {
    fn execute(&mut self, _batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
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
fn scan_executor_is_reached_only_after_authorization() {
    let error = scan(
        &request(),
        &mut FixtureAuthorizer,
        &registry().expect("built-in registry"),
        &mut RejectExecutor,
        &mut NoopClock,
    )
    .expect_err("fixture executor rejects after authorization");
    assert_eq!(error.classification().code, "io.test");
}
