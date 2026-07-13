// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::{
    capture::{Frame, LinkType},
    protocol::builtin::registry,
    workflow::{
        AddressFamily, Stats,
        clock::Clock,
        dns::{
            Exchange, Execution, ExecutionError, Executor, Limits, Outcome, QueryType, Request, run,
        },
        target::{AuthorizationError, Authorized, Authorizer, Target},
    },
};

struct LabAuthorizer;

impl Authorizer for LabAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, AuthorizationError> {
        assert_eq!(target, &Target::Hostname("resolver.lab".to_owned()));
        Ok(Authorized {
            declared: "resolver.lab".to_owned(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 56, 53))],
        })
    }

    fn authorize_operation(
        &mut self,
        packets: u64,
        maximum_wire_bytes: u64,
    ) -> Result<(), AuthorizationError> {
        assert_eq!(packets, 1);
        assert!(maximum_wire_bytes >= 12 + 14 + 20 + 8);
        Ok(())
    }
}

struct TimeoutExecutor;

impl Executor for TimeoutExecutor {
    fn execute(&mut self, exchange: &Exchange) -> Result<Execution, ExecutionError> {
        assert_eq!(
            exchange.probe.server_address,
            IpAddr::V4(Ipv4Addr::new(192, 168, 56, 53))
        );
        Ok(Execution {
            sent: exchange.probe.packet(),
            sent_evidence: Frame::new(
                UNIX_EPOCH + Duration::from_secs(1),
                LinkType::RAW,
                exchange.probe.query.clone(),
            )
            .unwrap(),
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: exchange.probe.query.len() as u64,
                elapsed: Duration::from_millis(10),
                capture: Default::default(),
            },
        })
    }
}

struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn downstream_code_can_inject_dns_authorization_execution_and_timing() {
    let request = Request {
        server: Target::Hostname("resolver.lab".to_owned()),
        address_family: AddressFamily::Ipv4,
        server_port: 53,
        source_port: 50_000,
        query_name: "www.example.test".to_owned(),
        query_type: QueryType::A,
        transaction_id: 0x5043,
        recursion_desired: true,
        attempts: 1,
        timeout: Duration::from_millis(100),
        queries_per_second: None,
        limits: Limits::default(),
    };
    let result = run(
        &request,
        &mut LabAuthorizer,
        &registry().unwrap(),
        &mut TimeoutExecutor,
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.server, "resolver.lab");
    assert_eq!(result.outcome, Outcome::Timeout);
    assert_eq!(result.attempts.len(), 1);
    assert_eq!(result.stats.packets_completed, 1);
}
