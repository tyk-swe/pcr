// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::time::Duration;

use packetcraftr::clock::CancellableClock;
use packetcraftr::fuzz::{self, Execution, ExecutionCase, LiveOptions, RunInput};
use packetcraftr::policy::{Authorizer, Operation};
use packetcraftr::probe::Executor;
use packetcraftr::progress::Runtime;
use packetcraftr_core::Packet;
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Kind};
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};

struct CancellingAuthorizer {
    signal: Cancellation,
    calls: usize,
}

impl Authorizer for CancellingAuthorizer {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        assert!(matches!(operation, Operation::Declared(_)));
        self.calls += 1;
        self.signal.cancel();
        Ok(())
    }
}

#[derive(Default)]
struct CountingExecutor(usize);

impl Executor<ExecutionCase> for CountingExecutor {
    fn execute(&mut self, _case: &ExecutionCase) -> Result<Execution, BoundaryError> {
        self.0 += 1;
        Err(BoundaryError::new(
            "cancelled campaign reached the executor",
            Classification::new("internal.fixture_execution", Kind::Internal, None),
            Vec::new(),
        ))
    }
}

#[test]
fn cancellation_at_entry_or_authorization_prevents_the_first_live_case() {
    for progressive in [false, true] {
        for cancelled_at_entry in [true, false] {
            let signal = Cancellation::default();
            if cancelled_at_entry {
                signal.cancel();
            }
            let request = packet_fuzz::Request {
                cases: 1,
                strategies: vec![packet_fuzz::Strategy::BitFlip],
                targets: vec!["2.bytes".parse().unwrap()],
                ..packet_fuzz::Request::default()
            };
            let mut packet = Packet::new();
            packet
                .push(Ipv4 {
                    source: Ipv4Addr::new(192, 0, 2, 1),
                    destination: Ipv4Addr::new(192, 0, 2, 2),
                    ..Ipv4::default()
                })
                .push(Udp {
                    destination_port: 9,
                    ..Udp::default()
                })
                .push(Raw::new(vec![1, 2, 3]));
            let input = RunInput {
                request: &request,
                live: LiveOptions {
                    timeout: Duration::from_millis(1),
                    ..LiveOptions::default()
                },
                packet,
                registry: packetcraftr_core::protocol::builtin::registry(),
            };
            let mut authorizer = CancellingAuthorizer {
                signal: signal.clone(),
                calls: 0,
            };
            let mut executor = CountingExecutor::default();
            let mut clock = CancellableClock(signal);
            let error = if progressive {
                fuzz::run_with_events(
                    input,
                    &mut authorizer,
                    &mut executor,
                    &mut clock,
                    &Runtime::default(),
                    |_| panic!("cancelled campaign must not publish a case"),
                )
                .unwrap_err()
            } else {
                fuzz::run(input, &mut authorizer, &mut executor, &mut clock).unwrap_err()
            };
            assert_eq!(executor.0, 0, "cancelled_at_entry={cancelled_at_entry}");
            assert_eq!(authorizer.calls, usize::from(!cancelled_at_entry));
            assert_eq!(error.classification().code, "io.cancelled");
        }
    }
}
