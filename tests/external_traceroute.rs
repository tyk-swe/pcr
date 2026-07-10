// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::{
    default_registry, traceroute, AuthorizedTracerouteTarget, CaptureStatistics, CapturedFrame,
    LinkType, TracerouteAddressFamily, TracerouteAuthorizationError, TracerouteAuthorizer,
    TracerouteBatch, TracerouteBatchExecution, TracerouteClock, TracerouteCompletion,
    TracerouteExecutionError, TracerouteExecutor, TracerouteLimits, TracerouteProbeStatus,
    TracerouteRequest, TracerouteStats, TracerouteStrategy, TracerouteTarget,
};

struct LabAuthorizer;

impl TracerouteAuthorizer for LabAuthorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &TracerouteTarget,
    ) -> Result<AuthorizedTracerouteTarget, TracerouteAuthorizationError> {
        assert_eq!(target, &TracerouteTarget::Hostname("device.lab".to_owned()));
        Ok(AuthorizedTracerouteTarget {
            declared: "device.lab".to_owned(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 56, 10))],
        })
    }

    fn authorize_operation(
        &mut self,
        packets: u64,
        maximum_wire_bytes: u64,
    ) -> Result<(), TracerouteAuthorizationError> {
        assert_eq!(packets, 1);
        assert_eq!(maximum_wire_bytes, 74);
        Ok(())
    }
}

struct TimeoutExecutor;

impl TracerouteExecutor for TimeoutExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, TracerouteExecutionError> {
        let mut sent = batch
            .probes
            .iter()
            .map(|probe| probe.packet())
            .collect::<Vec<_>>();
        sent[0].get_mut::<packetcraftr::Ipv4>().unwrap().source = Ipv4Addr::new(192, 168, 56, 1);
        let sent_evidence = vec![CapturedFrame::new(
            UNIX_EPOCH + Duration::from_secs(1),
            LinkType::RAW,
            vec![0x45],
        )
        .unwrap()];
        Ok(TracerouteBatchExecution {
            sent,
            sent_evidence,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: TracerouteStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: 1,
                elapsed: Duration::from_millis(1),
                capture: CaptureStatistics::default(),
            },
        })
    }
}

struct NoopClock;

impl TracerouteClock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn downstream_code_can_inject_traceroute_authorization_execution_and_timing() {
    let request = TracerouteRequest {
        target: TracerouteTarget::Hostname("device.lab".to_owned()),
        strategy: TracerouteStrategy::Udp,
        address_family: TracerouteAddressFamily::Ipv4,
        destination_port: Some(33_434),
        first_hop: 1,
        max_hops: 1,
        probes_per_hop: 1,
        timeout: Duration::from_millis(10),
        probes_per_second: None,
        limits: TracerouteLimits::default(),
    };
    let result = traceroute(
        &request,
        &mut LabAuthorizer,
        &default_registry().unwrap(),
        &mut TimeoutExecutor,
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.target, "device.lab");
    assert_eq!(result.completion, TracerouteCompletion::Timeout);
    assert_eq!(result.hops.len(), 1);
    assert_eq!(result.hops[0].probes.len(), 1);
    assert_eq!(
        result.hops[0].probes[0].status,
        TracerouteProbeStatus::Timeout
    );
}
