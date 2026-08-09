// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_packet::error::{Classified, Kind};
use packetcraftr_packet::frame::{Frame, LinkType};
use packetcraftr_packet::protocol::builtin::registry as default_registry;

use crate::clock::Clock;
use crate::target::{Authorized, Authorizer, Family, Target};
use crate::{BoundaryError, Stats};

use super::DEFAULT_DNS_SERVER_PORT;
use super::engine::dns;
use super::model::{
    DnsExchange, DnsExchangeExecution, DnsExecutor, DnsLimits, DnsQueryType, DnsRequest,
};

#[derive(Default)]
struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct SingleAddressAuthorizer {
    address: IpAddr,
}

impl Authorizer for SingleAddressAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.clone(),
            addresses: vec![self.address],
        })
    }

    fn authorize_operation(
        &mut self,
        _packets: u64,
        _maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct UntimestampedSentExecutor;

impl DnsExecutor for UntimestampedSentExecutor {
    fn execute(&mut self, exchange: &DnsExchange) -> Result<DnsExchangeExecution, BoundaryError> {
        let sent = exchange.probe.packet();
        let sent_evidence = Frame::without_timestamp(LinkType::RAW, Bytes::from_static(&[0x45]))
            .expect("fixture frame");
        Ok(DnsExchangeExecution {
            sent,
            sent_evidence,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: 1,
                elapsed: Duration::from_millis(1),
                ..Stats::default()
            },
        })
    }
}

fn dns_request(address: IpAddr) -> DnsRequest {
    DnsRequest {
        server: Target::Address(address),
        address_family: Family::Any,
        server_port: DEFAULT_DNS_SERVER_PORT,
        source_port: 49_152,
        query_name: "example.com".to_owned(),
        query_type: DnsQueryType::A,
        transaction_id: 0x1234,
        recursion_desired: true,
        attempts: 1,
        timeout: Duration::from_millis(1),
        queries_per_second: None,
        limits: DnsLimits::default(),
    }
}

#[test]
fn dns_executor_evidence_requires_sent_timestamp() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    let error = dns(
        &dns_request(address),
        &mut SingleAddressAuthorizer { address },
        &default_registry().expect("built-in registry"),
        &mut UntimestampedSentExecutor,
        &mut NoopClock,
    )
    .expect_err("untimestamped sent evidence must be rejected");

    assert_eq!(error.classification().kind, Kind::Internal);
    assert_eq!(error.classification().code, "internal.dns_evidence");
    assert!(error.to_string().contains("sent frame without a timestamp"));
}
