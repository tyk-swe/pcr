// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{
    default_registry, fuzz, fuzz_live, BuildContext, BuildOptions, Builder, CapturedFrame,
    ErrorClassification, FailureKind, FuzzAuthorizationError, FuzzAuthorizer, FuzzCaseExecution,
    FuzzCaseOutcome, FuzzClock, FuzzExecutionCase, FuzzExecutionError, FuzzExecutionStats,
    FuzzExecutor, FuzzLiveOptions, FuzzRequest, FuzzStrategy, FuzzTarget, LinkType, Packet,
    ProtocolRegistry, Raw,
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
    ) -> Result<(), FuzzAuthorizationError> {
        self.calls += 1;
        assert_eq!(packets.len(), 2);
        assert!(maximum_wire_bytes >= 2);
        assert!(!requires_malformed_live);
        Ok(())
    }
}

struct Executor {
    registry: Arc<ProtocolRegistry>,
    calls: usize,
}

impl FuzzExecutor for Executor {
    fn execute(
        &mut self,
        case: &FuzzExecutionCase,
        _timeout: Duration,
    ) -> Result<FuzzCaseExecution, FuzzExecutionError> {
        self.calls += 1;
        let built = Builder::new(Arc::clone(&self.registry))
            .build(
                case.packet.clone(),
                BuildContext::default(),
                BuildOptions::default(),
            )
            .map_err(|source| {
                FuzzExecutionError::new(
                    source.to_string(),
                    ErrorClassification::new("packet.external_fuzz", FailureKind::Packet, None),
                    Vec::new(),
                )
            })?;
        let sent =
            CapturedFrame::new(std::time::UNIX_EPOCH, LinkType(147), built.bytes.clone()).unwrap();
        Ok(FuzzCaseExecution {
            stats: FuzzExecutionStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: built.bytes.len() as u64,
                ..FuzzExecutionStats::default()
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
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![0_u8]));
    let request = FuzzRequest {
        seed: 11,
        cases: 2,
        strategies: vec![FuzzStrategy::BitFlip],
        targets: vec![FuzzTarget {
            layer: 0,
            field: "bytes".to_owned(),
        }],
        ..FuzzRequest::default()
    };

    // The offline API has no authorizer, executor, resolver, route, or clock
    // parameter and therefore cannot produce network side effects.
    let offline = fuzz(&request, packet.clone(), Arc::clone(&registry)).unwrap();
    assert_eq!(offline.cases.len(), 2);
    assert!(offline
        .cases
        .iter()
        .all(|case| case.outcome == FuzzCaseOutcome::Built));

    let mut authorizer = Authorizer { calls: 0 };
    let mut executor = Executor {
        registry: Arc::clone(&registry),
        calls: 0,
    };
    let mut clock = Clock::default();
    let live = fuzz_live(
        &request,
        FuzzLiveOptions {
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
    assert!(live
        .cases
        .iter()
        .all(|case| case.outcome == FuzzCaseOutcome::Timeout));
    assert_eq!(
        live.cases[1].reproduction.case_seed,
        offline.cases[1].reproduction.case_seed
    );
}
