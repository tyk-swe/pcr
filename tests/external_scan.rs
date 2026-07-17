// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::{
    capture::{Frame, LinkType},
    protocol::{builtin::registry, network::Ipv4},
    workflow::{
        AddressFamily, BoundaryError, Stats,
        clock::Clock,
        scan::{
            Batch, Classification, Execution, Executor, Limits, ProbeStatus, Request, Transport,
            run,
        },
        target::{Authorized, Authorizer, Target},
    },
};

struct LabAuthorizer;

impl Authorizer for LabAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        assert_eq!(target, &Target::Hostname("device.lab".to_owned()));
        Ok(Authorized {
            declared: "device.lab".to_owned(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 56, 10))],
        })
    }

    fn authorize_operation(
        &mut self,
        packets: u64,
        maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError> {
        assert_eq!(packets, 1);
        assert!(maximum_wire_bytes >= 40);
        Ok(())
    }
}

struct TimeoutExecutor;

impl Executor for TimeoutExecutor {
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        assert_eq!(batch.probes.len(), 1);
        let probe = &batch.probes[0];
        let mut packet = probe.packet();
        packet.get_mut::<Ipv4>().unwrap().source = Ipv4Addr::new(192, 168, 56, 1);
        let sent = Frame::new(
            UNIX_EPOCH + Duration::from_secs(1),
            LinkType::RAW,
            vec![0x45; 40],
        )
        .unwrap();
        Ok(Execution {
            sent: vec![packet],
            sent_evidence: vec![sent],
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: 40,
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
fn downstream_code_can_inject_scan_authorization_execution_and_timing() {
    let request = Request {
        target: Target::Hostname("device.lab".to_owned()),
        transport: Transport::Tcp,
        address_family: AddressFamily::Ipv4,
        ports: vec![443],
        attempts: 1,
        timeout: Duration::from_millis(100),
        probes_per_second: Some(10),
        limits: Limits::default(),
    };
    let registry = registry().unwrap();
    let result = run(
        &request,
        &mut LabAuthorizer,
        &registry,
        &mut TimeoutExecutor,
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.target, "device.lab");
    assert_eq!(result.endpoints.len(), 1);
    assert_eq!(result.endpoints[0].port, Some(443));
    assert_eq!(result.endpoints[0].classification, Classification::Timeout);
    assert_eq!(result.endpoints[0].evidence[0].status, ProbeStatus::Timeout);
    assert_eq!(result.stats.packets_completed, 1);
}
