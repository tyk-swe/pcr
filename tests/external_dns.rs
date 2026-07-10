// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::{
    default_registry, dns, AuthorizedDnsTarget, CapturedFrame, DnsAddressFamily,
    DnsAuthorizationError, DnsAuthorizer, DnsClock, DnsExchange, DnsExchangeExecution,
    DnsExecutionError, DnsExecutor, DnsLimits, DnsOutcome, DnsQueryType, DnsRequest, DnsStats,
    DnsTarget, LinkType,
};

struct LabAuthorizer;

impl DnsAuthorizer for LabAuthorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &DnsTarget,
    ) -> Result<AuthorizedDnsTarget, DnsAuthorizationError> {
        assert_eq!(target, &DnsTarget::Hostname("resolver.lab".to_owned()));
        Ok(AuthorizedDnsTarget {
            declared: "resolver.lab".to_owned(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 56, 53))],
        })
    }

    fn authorize_operation(
        &mut self,
        packets: u64,
        maximum_wire_bytes: u64,
    ) -> Result<(), DnsAuthorizationError> {
        assert_eq!(packets, 1);
        assert!(maximum_wire_bytes >= 12 + 14 + 20 + 8);
        Ok(())
    }
}

struct TimeoutExecutor;

impl DnsExecutor for TimeoutExecutor {
    fn execute(
        &mut self,
        exchange: &DnsExchange,
    ) -> Result<DnsExchangeExecution, DnsExecutionError> {
        assert_eq!(
            exchange.probe.server_address,
            IpAddr::V4(Ipv4Addr::new(192, 168, 56, 53))
        );
        Ok(DnsExchangeExecution {
            sent: exchange.probe.packet(),
            sent_evidence: CapturedFrame::new(
                UNIX_EPOCH + Duration::from_secs(1),
                LinkType::RAW,
                exchange.probe.query.clone(),
            )
            .unwrap(),
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: DnsStats {
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

impl DnsClock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn downstream_code_can_inject_dns_authorization_execution_and_timing() {
    let request = DnsRequest {
        server: DnsTarget::Hostname("resolver.lab".to_owned()),
        address_family: DnsAddressFamily::Ipv4,
        server_port: 53,
        source_port: 50_000,
        query_name: "www.example.test".to_owned(),
        query_type: DnsQueryType::A,
        transaction_id: 0x5043,
        recursion_desired: true,
        attempts: 1,
        timeout: Duration::from_millis(100),
        queries_per_second: None,
        limits: DnsLimits::default(),
    };
    let result = dns(
        &request,
        &mut LabAuthorizer,
        &default_registry().unwrap(),
        &mut TimeoutExecutor,
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.server, "resolver.lab");
    assert_eq!(result.outcome, DnsOutcome::Timeout);
    assert_eq!(result.attempts.len(), 1);
    assert_eq!(result.stats.packets_completed, 1);
}
