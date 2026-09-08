// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use packetcraftr::clock::CancellableClock;
use packetcraftr::dns::{self, Exchange, Execution, TcpExecutor};
use packetcraftr::policy::{Authorizer, Operation, Policy};
use packetcraftr::probe::Executor;
use packetcraftr::progress::Runtime;
use packetcraftr::target::{Authorized, Family, Hostname, Resolver, Target};
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Kind};

struct CancellingAuthorizer {
    signal: Cancellation,
    cancel_during_resolution: bool,
    resolutions: usize,
}

impl Authorizer for CancellingAuthorizer {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        assert!(matches!(operation, Operation::Dns(_)));
        if !self.cancel_during_resolution {
            self.signal.cancel();
        }
        Ok(())
    }

    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        self.resolutions += 1;
        Policy {
            allow_hostname_resolution: true,
            ..Policy::default()
        }
        .resolve_target(target, self)
        .map_err(BoundaryError::from_error)
    }
}

impl Resolver for CancellingAuthorizer {
    fn resolve(
        &self,
        _hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, packetcraftr::target::Error> {
        self.signal.cancel();
        Ok(vec![Ipv4Addr::new(192, 0, 2, 53).into()])
    }
}

#[derive(Default)]
struct CountingExecutor(usize);

impl Executor<Exchange> for CountingExecutor {
    fn execute(&mut self, _exchange: &Exchange) -> Result<Execution, BoundaryError> {
        self.0 += 1;
        Err(BoundaryError::new(
            "cancelled DNS operation reached the executor",
            Classification::new("internal.fixture_execution", Kind::Internal, None),
            Vec::new(),
        ))
    }
}

impl TcpExecutor for CountingExecutor {}

#[test]
fn cancellation_during_authorization_or_resolution_prevents_dns_execution() {
    for progressive in [false, true] {
        for cancel_during_resolution in [true, false] {
            let signal = Cancellation::default();
            let request = dns::Request {
                server: "dns.example.test".parse().unwrap(),
                address_family: Family::Any,
                server_port: 53,
                source_port: 40_000,
                query_name: "example.test".to_owned(),
                query_type: dns::QueryType::A,
                transaction_id: 0x1234,
                recursion_desired: true,
                tcp_fallback: false,
                attempts: 1,
                timeout: Duration::from_secs(1),
                queries_per_second: None,
                limits: dns::Limits::default(),
            };
            let mut authorizer = CancellingAuthorizer {
                signal: signal.clone(),
                cancel_during_resolution,
                resolutions: 0,
            };
            let registry = packetcraftr_core::protocol::builtin::registry();
            let mut executor = CountingExecutor::default();
            let mut clock = CancellableClock(signal);
            let error = if progressive {
                dns::run_with_events(
                    &request,
                    &mut authorizer,
                    &registry,
                    &mut executor,
                    &mut clock,
                    &Runtime::default(),
                    |_| panic!("cancelled DNS operation must not publish an event"),
                )
                .unwrap_err()
            } else {
                dns::run(
                    &request,
                    &mut authorizer,
                    &registry,
                    &mut executor,
                    &mut clock,
                )
                .unwrap_err()
            };
            assert_eq!(executor.0, 0);
            assert_eq!(
                authorizer.resolutions,
                usize::from(cancel_during_resolution)
            );
            assert_eq!(error.classification().code, "io.cancelled");
        }
    }
}
