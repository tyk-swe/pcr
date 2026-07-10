// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::{
    scan, AuthorizedScanTarget, CapturedFrame, LinkType, ScanAddressFamily, ScanAuthorizationError,
    ScanAuthorizer, ScanBatch, ScanBatchExecution, ScanClassification, ScanClock,
    ScanExecutionError, ScanExecutor, ScanLimits, ScanProbeStatus, ScanRequest, ScanStats,
    ScanTarget, ScanTransport,
};

struct LabAuthorizer;

impl ScanAuthorizer for LabAuthorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &ScanTarget,
    ) -> Result<AuthorizedScanTarget, ScanAuthorizationError> {
        assert_eq!(target, &ScanTarget::Hostname("device.lab".to_owned()));
        Ok(AuthorizedScanTarget {
            declared: "device.lab".to_owned(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 56, 10))],
        })
    }

    fn authorize_operation(
        &mut self,
        packets: u64,
        maximum_wire_bytes: u64,
    ) -> Result<(), ScanAuthorizationError> {
        assert_eq!(packets, 1);
        assert!(maximum_wire_bytes >= 40);
        Ok(())
    }
}

struct TimeoutExecutor;

impl ScanExecutor for TimeoutExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError> {
        assert_eq!(batch.probes.len(), 1);
        let probe = &batch.probes[0];
        let mut packet = probe.packet();
        packet.get_mut::<packetcraftr::Ipv4>().unwrap().source = Ipv4Addr::new(192, 168, 56, 1);
        let sent = CapturedFrame::new(
            UNIX_EPOCH + Duration::from_secs(1),
            LinkType::RAW,
            vec![0x45],
        )
        .unwrap();
        Ok(ScanBatchExecution {
            sent: vec![packet],
            sent_evidence: vec![sent],
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: ScanStats {
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

impl ScanClock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn downstream_code_can_inject_scan_authorization_execution_and_timing() {
    let request = ScanRequest {
        target: ScanTarget::Hostname("device.lab".to_owned()),
        transport: ScanTransport::Tcp,
        address_family: ScanAddressFamily::Ipv4,
        ports: vec![443],
        attempts: 1,
        timeout: Duration::from_millis(100),
        probes_per_second: Some(10),
        limits: ScanLimits::default(),
    };
    let registry = packetcraftr::default_registry().unwrap();
    let result = scan(
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
    assert_eq!(
        result.endpoints[0].classification,
        ScanClassification::Timeout
    );
    assert_eq!(
        result.endpoints[0].evidence[0].status,
        ScanProbeStatus::Timeout
    );
    assert_eq!(result.stats.packets_completed, 1);
}
