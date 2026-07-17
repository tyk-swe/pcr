// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{
    capture::{Frame, LinkType},
    error::{Classification, Kind},
    packet::{
        Packet,
        build::{Builder, Context, Options},
        layer::Raw,
        registry::Registry,
    },
    protocol::builtin::registry,
    workflow::{
        BoundaryError, Stats,
        clock::Clock as FuzzClock,
        fuzz::{
            Authorizer as FuzzAuthorizer, CaseOutcome, Execution, ExecutionCase,
            Executor as FuzzExecutor, LiveOptions, Request, Strategy, Target, run, run_live,
        },
    },
};

struct Authorizer {
    calls: usize,
}

impl FuzzAuthorizer for Authorizer {
    fn authorize_operation(
        &mut self,
        packets: &[Packet],
        _destination: Option<IpAddr>,
        maximum_wire_bytes: u64,
        requires_malformed_live: bool,
    ) -> Result<(), BoundaryError> {
        self.calls += 1;
        assert_eq!(packets.len(), 2);
        assert!(maximum_wire_bytes >= 2);
        assert!(!requires_malformed_live);
        Ok(())
    }
}

struct Executor {
    registry: Arc<Registry>,
    calls: usize,
}

impl FuzzExecutor for Executor {
    fn execute(
        &mut self,
        case: &ExecutionCase,
        _timeout: Duration,
    ) -> Result<Execution, BoundaryError> {
        self.calls += 1;
        let built = Builder::new(Arc::clone(&self.registry))
            .build(case.packet.clone(), Context::default(), Options::default())
            .map_err(|source| {
                BoundaryError::new(
                    source.to_string(),
                    Classification::new("packet.external_fuzz", Kind::Packet, None),
                    Vec::new(),
                )
            })?;
        let sent = Frame::new(std::time::UNIX_EPOCH, LinkType(147), built.bytes.clone()).unwrap();
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
struct Clock {
    sleeps: usize,
}

impl FuzzClock for Clock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        self.sleeps += 1;
        Ok(())
    }
}

#[test]
fn downstream_code_can_run_offline_or_inject_live_fuzz_boundaries() {
    let registry = Arc::new(registry().unwrap());
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![0_u8]));
    let request = Request {
        seed: 11,
        cases: 2,
        strategies: vec![Strategy::BitFlip],
        targets: vec![Target {
            layer: 0,
            field: "bytes".to_owned(),
        }],
        ..Request::default()
    };

    // The offline API has no authorizer, executor, resolver, route, or clock
    // parameter and therefore cannot produce network side effects.
    let offline = run(&request, packet.clone(), Arc::clone(&registry)).unwrap();
    assert_eq!(offline.cases.len(), 2);
    assert!(
        offline
            .cases
            .iter()
            .all(|case| case.outcome == CaseOutcome::Built)
    );

    let mut authorizer = Authorizer { calls: 0 };
    let mut executor = Executor {
        registry: Arc::clone(&registry),
        calls: 0,
    };
    let mut clock = Clock::default();
    let live = run_live(
        &request,
        LiveOptions {
            timeout: Duration::from_millis(1),
            cases_per_second: Some(1_000),
            destination: None,
            allow_malformed_live: false,
        },
        packet,
        registry,
        &mut authorizer,
        &mut executor,
        &mut clock,
    )
    .unwrap();
    assert_eq!(authorizer.calls, 1);
    assert_eq!(executor.calls, 2);
    assert_eq!(clock.sleeps, 1);
    assert!(
        live.cases
            .iter()
            .all(|case| case.outcome == CaseOutcome::Timeout)
    );
    assert_eq!(
        live.cases[1].reproduction.case_seed,
        offline.cases[1].reproduction.case_seed
    );
}
