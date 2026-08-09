// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_packet::error::Classified;
use packetcraftr_packet::frame::{Frame, LinkType};
use packetcraftr_packet::fuzz as packet_fuzz;
use packetcraftr_packet::protocol::{
    builtin::registry as default_registry, network::Ipv4, transport::Udp,
};
use packetcraftr_packet::{
    Packet,
    build::{Builder, Context, Options},
    layer::Raw,
    registry::Registry,
};

use crate::clock::Clock;
use crate::{BoundaryError, Stats};

use super::{Authorizer, Execution, ExecutionCase, Executor, LiveOptions, run};

struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize_operation(
        &mut self,
        _packets: &[Packet],
        _destination: Option<std::net::IpAddr>,
        _maximum_wire_bytes: u64,
        _requires_malformed_live: bool,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct RebuildingExecutor {
    registry: Arc<Registry>,
}

impl Executor for RebuildingExecutor {
    fn execute(
        &mut self,
        case: &ExecutionCase,
        _timeout: Duration,
    ) -> Result<Execution, BoundaryError> {
        let built = Builder::new(Arc::clone(&self.registry))
            .build(case.packet.clone(), Context::default(), Options::default())
            .expect("prepared case must rebuild");
        let sent = Frame::new(SystemTime::UNIX_EPOCH, LinkType::IPV4, built.bytes.clone())
            .expect("built packet is a valid frame");
        Ok(Execution {
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: built.bytes.len() as u64,
                ..Stats::default()
            },
            built,
            sent,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        })
    }
}

struct UntimestampedFuzzExecutor {
    registry: Arc<Registry>,
}

impl Executor for UntimestampedFuzzExecutor {
    fn execute(
        &mut self,
        case: &ExecutionCase,
        _timeout: Duration,
    ) -> Result<Execution, BoundaryError> {
        let built = Builder::new(Arc::clone(&self.registry))
            .build(case.packet.clone(), Context::default(), Options::default())
            .expect("prepared case must rebuild");
        let sent = Frame::without_timestamp(LinkType::IPV4, built.bytes.clone())
            .expect("built packet is a valid frame");
        Ok(Execution {
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: built.bytes.len() as u64,
                ..Stats::default()
            },
            built,
            sent,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        })
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

fn packet() -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4::default())
        .push(Udp {
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"campaign")));
    packet
}

#[test]
fn live_execution_uses_the_identical_packet_campaign() {
    let registry = Arc::new(default_registry().expect("built-in registry"));
    let request = packet_fuzz::Request {
        seed: 0x5eed,
        cases: 8,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let offline =
        packet_fuzz::run(&request, packet(), Arc::clone(&registry)).expect("offline campaign");
    let mut authorizer = AllowAll;
    let mut executor = RebuildingExecutor {
        registry: Arc::clone(&registry),
    };
    let live = run(
        &request,
        LiveOptions {
            timeout: Duration::from_millis(1),
            ..LiveOptions::default()
        },
        packet(),
        registry,
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect("live campaign");

    assert_eq!(offline.cases.len(), live.cases.len());
    for (offline, live) in offline.cases.iter().zip(&live.cases) {
        assert_eq!(offline.index, live.index);
        assert_eq!(offline.seed, live.seed);
        assert_eq!(offline.mutation, live.mutation);
        assert_eq!(offline.shrink_values, live.shrink_values);
        assert_eq!(
            offline.built.as_ref().map(|built| built.bytes.as_ref()),
            live.built.as_ref().map(|built| built.bytes.as_ref())
        );
    }
}

#[test]
fn live_fuzz_executor_evidence_requires_sent_timestamp() {
    let registry = Arc::new(default_registry().expect("built-in registry"));
    let request = packet_fuzz::Request {
        cases: 1,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = AllowAll;
    let mut executor = UntimestampedFuzzExecutor {
        registry: Arc::clone(&registry),
    };
    let error = run(
        &request,
        LiveOptions {
            timeout: Duration::from_millis(1),
            ..LiveOptions::default()
        },
        packet(),
        registry,
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("untimestamped sent evidence must be rejected");

    assert_eq!(error.classification().code, "internal.fuzz_evidence");
    assert!(error.to_string().contains("sent frame without a timestamp"));
}
