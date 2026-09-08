// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use packetcraftr::clock::CancellableClock;
use packetcraftr::fuzz::{self, Execution, ExecutionCase, LiveOptions, RunInput};
use packetcraftr::policy::{Authorizer, Operation};
use packetcraftr::probe::Executor;
use packetcraftr::progress::Runtime;
use packetcraftr_core::Packet;
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::codec::{self, LayerCodec};
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Kind};
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::layer::{Id, Layer, Raw};
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr_core::registry::Registry;

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

#[derive(Debug)]
struct CancellingCodec {
    inner: Arc<dyn LayerCodec>,
    signal: Cancellation,
    builds: Arc<AtomicUsize>,
}

impl LayerCodec for CancellingCodec {
    fn protocol_id(&self) -> &'static Id {
        self.inner.protocol_id()
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &codec::LayerEncodeContext<'_>,
    ) -> Result<codec::EncodedLayer, codec::Error> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        let encoded = self.inner.encode(layer, payload, context)?;
        self.signal.cancel();
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        context: &codec::LayerDecodeContext<'_>,
    ) -> Result<codec::DecodedLayer, codec::Error> {
        self.inner.decode(input, context)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, codec::Error> {
        self.inner.make_layer(fields)
    }
}

#[test]
fn cancellation_during_preparation_stops_generation_before_live_budget_validation() {
    for progressive in [false, true] {
        for cases in [1, 3] {
            let signal = Cancellation::default();
            let builds = Arc::new(AtomicUsize::new(0));
            let mut registry = Registry::builder();
            registry
                .register_codec(
                    CancellingCodec {
                        inner: packetcraftr_core::protocol::builtin::registry()
                            .codec("raw")
                            .unwrap()
                            .clone(),
                        signal: signal.clone(),
                        builds: builds.clone(),
                    },
                    &[],
                )
                .unwrap();
            let request = packet_fuzz::Request {
                cases,
                strategies: vec![packet_fuzz::Strategy::BitFlip],
                targets: vec!["0.bytes".parse().unwrap()],
                limits: packet_fuzz::Limits {
                    max_duration: Duration::from_secs(60),
                    ..packet_fuzz::Limits::default()
                },
                ..packet_fuzz::Request::default()
            };
            let mut packet = Packet::new();
            packet.push(Raw::new(vec![1, 2, 3]));
            let input = RunInput {
                request: &request,
                live: LiveOptions {
                    // Preparation plus even one live case would exceed the budget.
                    timeout: request.limits.max_duration,
                    ..LiveOptions::default()
                },
                packet,
                registry: Arc::new(registry.build().unwrap()),
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
                    |_| panic!("cancelled preparation must not publish a case"),
                )
                .unwrap_err()
            } else {
                fuzz::run(input, &mut authorizer, &mut executor, &mut clock).unwrap_err()
            };
            assert_eq!(builds.load(Ordering::SeqCst), 1);
            assert_eq!(authorizer.calls, 0);
            assert_eq!(executor.0, 0);
            assert_eq!(error.classification().code, "io.cancelled");
        }
    }
}
