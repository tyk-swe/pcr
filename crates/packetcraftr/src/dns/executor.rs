// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic};

use crate::Stats;
use crate::clock::Clock;
use crate::correlation::{self, Transport as ProbeTransport};
use crate::evidence::ExecutionPermit;
use crate::execution::{ExchangeExecutor, Executor, ExecutorFault, WorkflowOverrides};
use crate::providers::{PacketProviders, TcpProviders};
use packetcraftr_core::error::BoundaryError;

use super::Limits;
use super::evidence::{ResponseClassification, classify_response};
use super::plan::Probe;

/// One bounded UDP DNS query the executor transmits with capture armed first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Exchange {
    pub(crate) probe: Probe,
    pub(crate) timeout: Duration,
    pub(crate) limits: Limits,
    pub(crate) permit: ExecutionPermit,
}

#[derive(Clone, Debug)]
pub(crate) struct ExchangeEvidence {
    pub(crate) permit: ExecutionPermit,
    pub(crate) sent: crate::evidence::SentPacket,
    pub(crate) responses: Vec<crate::exchange::Response>,
    pub(crate) unsolicited: Vec<DecodedPacket>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: Stats,
}

impl crate::execution::Receipt for ExchangeEvidence {
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }

    fn stats(&self) -> &Stats {
        &self.stats
    }
}

impl crate::execution::Step for Exchange {
    type Evidence = ExchangeEvidence;
}

/// It runs on a kernel socket, so it is a query, not an exchange: nothing is captured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TcpQuery {
    pub(crate) endpoint: SocketAddr,
    /// Exact DNS query message without the TCP length prefix.
    pub(crate) query: Bytes,
    pub(crate) timeout: Duration,
    pub(crate) max_message_bytes: usize,
    pub(crate) permit: ExecutionPermit,
}

#[derive(Clone, Debug)]
pub(crate) struct TcpEvidence {
    pub(crate) permit: ExecutionPermit,
    pub(crate) response: super::tcp::Response,
}

pub(crate) trait TcpQuerier {
    /// Expected socket and framing failures are typed data, so normal retry precedence applies.
    fn query(&mut self, query: &TcpQuery) -> Result<TcpEvidence, super::tcp::Error>;
}

const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.dns_executor",
    "use one bounded UDP DNS query and retain at least one response",
);
const RESULT_FAULT: ExecutorFault = ExecutorFault::new(
    "internal.dns_executor",
    "treat the DNS operation as incomplete because client evidence was inconsistent",
);

/// Checks the capture boundary without preparing a route or doing any I/O.
pub(super) fn validate_capture(
    limits: &Limits,
    collection: &crate::exchange::Collection,
) -> Result<(), BoundaryError> {
    let max_responses = limits.evidence.max_frames;
    if max_responses == 0 {
        return Err(EXECUTOR_FAULT.invalid("DNS exchange must retain at least one response"));
    }
    if max_responses > collection.max_responses {
        return Err(EXECUTOR_FAULT.invalid(format!(
            "DNS exchange requests {} responses but the client is bounded to {}",
            max_responses, collection.max_responses
        )));
    }
    // Captured evidence must fit the request's bounds; refuse before any I/O, not after.
    let capture = &collection.capture;
    if capture.max_frames > max_responses || capture.max_bytes > limits.evidence.max_bytes {
        return Err(EXECUTOR_FAULT.invalid(format!(
                "the client captures up to {} frames and {} bytes but the DNS exchange retains at most {} frames and {} bytes",
                capture.max_frames,
                capture.max_bytes,
                max_responses,
                limits.evidence.max_bytes
            )));
    }
    collection.validate().map_err(BoundaryError::from_error)
}

impl<P: PacketProviders, K: Clock> Executor<Exchange> for ExchangeExecutor<'_, P, K> {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        validate_capture(&exchange.limits, &self.collection)?;
        let max_responses = exchange.limits.evidence.max_frames;
        let registry = std::sync::Arc::clone(self.client.registry());
        let stop_probe = exchange.probe.clone();
        let stop_limits = exchange.limits.message;
        let mut matches_request =
            |_request_index: usize,
             sent: &packetcraftr_core::packet::Packet,
             response: &packetcraftr_core::decode::DecodedPacket| {
                correlation::observe(self.client.registry(), ProbeTransport::Udp, sent, response)
                    .is_some()
            };
        let mut stop_after_response =
            |_request_index: usize,
             sent: &packetcraftr_core::packet::Packet,
             response: &packetcraftr_core::decode::DecodedPacket| {
                matches!(
                    classify_response(&registry, &stop_probe, sent, response, stop_limits),
                    Some(ResponseClassification::Response(_))
                )
            };
        let result = self.exchange_for_workflow(
            packetcraftr_core::template::Template::new(exchange.probe.packet()),
            WorkflowOverrides {
                timeout: exchange.timeout,
                max_template_packets: 1,
                destination: exchange.probe.server_address,
                interface: None,
                max_responses: Some(max_responses),
            },
            &mut matches_request,
            Some(&mut stop_after_response),
        )?;
        let crate::exchange::Aggregate {
            mut sent,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = result.aggregate;
        if sent.len() != 1 {
            return Err(RESULT_FAULT
                .internal("single-query DNS exchange returned an invalid sent-evidence count"));
        }
        if responses.iter().any(|response| response.request_index != 0) {
            return Err(RESULT_FAULT.internal(
                "single-query DNS exchange returned a response for an unknown request index",
            ));
        }
        Ok(ExchangeEvidence {
            permit: exchange.permit,
            sent: crate::exchange::into_sent_packet(sent.pop().expect("validated one sent packet")),
            responses,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        })
    }
}

/// Kernel TCP honors no route override: `Request::validate` refuses them before any query.
impl<P: TcpProviders, K: Clock> TcpQuerier for ExchangeExecutor<'_, P, K> {
    fn query(&mut self, query: &TcpQuery) -> Result<TcpEvidence, super::tcp::Error> {
        let response = super::tcp::query(
            super::tcp::Request {
                endpoint: query.endpoint,
                query: &query.query,
                timeout: query.timeout,
                cancellation: self.client.cancellation.as_ref(),
                max_message_bytes: query.max_message_bytes,
            },
            std::sync::Arc::new(crate::providers::TcpOf(std::sync::Arc::clone(
                &self.client.providers,
            ))),
        )?;
        Ok(TcpEvidence {
            permit: query.permit,
            response,
        })
    }
}
