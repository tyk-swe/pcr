// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use packetcraftr_core::{Packet, decode::DecodedPacket, frame::Frame, frame::LinkType};

use crate::clock::Clock;
use crate::target::{Authorized, Authorizer, Family, Target};
use crate::{BoundaryError, Stats};

use super::DEFAULT_DNS_SERVER_PORT;

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

struct TrustedReceiptExecutor;

impl super::model::Executor for TrustedReceiptExecutor {
    fn execute(
        &mut self,
        exchange: &super::model::Exchange,
    ) -> Result<super::model::Execution, BoundaryError> {
        let sent = crate::evidence::test_sent_packet(exchange.probe.packet());
        let bytes = u64::try_from(sent.bytes_sent()).unwrap();
        Ok(super::model::Execution {
            permit: exchange.permit,
            sent,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes,
                elapsed: Duration::from_millis(1),
                ..Stats::default()
            },
        })
    }
}

struct InvalidResponseIndexExecutor;

impl super::model::Executor for InvalidResponseIndexExecutor {
    fn execute(
        &mut self,
        exchange: &super::model::Exchange,
    ) -> Result<super::model::Execution, BoundaryError> {
        let mut execution = TrustedReceiptExecutor.execute(exchange)?;
        let frame = Frame::without_timestamp(LinkType::RAW, &[0_u8][..]).expect("evidence frame");
        execution.responses.push(crate::exchange::Response {
            request_index: 1,
            response: DecodedPacket {
                packet: Packet::new(),
                original: frame.bytes().clone(),
                frame,
                layout: packetcraftr_core::layout::PacketLayout::default(),
                diagnostics: Vec::new(),
            },
            latency: Duration::ZERO,
        });
        Ok(execution)
    }
}

fn dns_request(address: IpAddr) -> super::model::Request {
    super::model::Request {
        server: Target::Address(address),
        address_family: Family::Any,
        server_port: DEFAULT_DNS_SERVER_PORT,
        source_port: 49_152,
        query_name: "example.com".to_owned(),
        query_type: super::model::QueryType::A,
        transaction_id: 0x1234,
        recursion_desired: true,
        attempts: 1,
        timeout: Duration::from_millis(1),
        queries_per_second: None,
        limits: super::model::Limits::default(),
    }
}

#[test]
fn dns_executor_success_uses_trusted_sent_timestamp() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    super::engine::run(
        &dns_request(address),
        &mut SingleAddressAuthorizer { address },
        &packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
        &mut TrustedReceiptExecutor,
        &mut NoopClock,
    )
    .expect("trusted receipt provides send timing");
}

#[test]
fn dns_executor_rejects_nonzero_response_index() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    let error = super::engine::run(
        &dns_request(address),
        &mut SingleAddressAuthorizer { address },
        &packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
        &mut InvalidResponseIndexExecutor,
        &mut NoopClock,
    )
    .expect_err("nonzero DNS response index must be rejected");

    assert!(
        error
            .to_string()
            .contains("response for an unknown request index")
    );
}
