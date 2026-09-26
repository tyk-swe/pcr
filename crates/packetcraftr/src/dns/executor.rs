// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The DNS executor seam: the capture-armed UDP [`Exchange`] every attempt
//! runs, and the optional DNS-over-TCP [`TcpQuerier`] capability, both served
//! by the client's exchange executor.

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
use crate::providers::Providers;
use packetcraftr_core::error::BoundaryError;

use super::Limits;
use super::classification::{ResponseClassification, classify_response};
use super::probe::Probe;

/// One bounded UDP DNS query the executor transmits with capture armed first.
///
/// Response retention is bounded by `limits.max_evidence_frames`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Exchange {
    pub(crate) probe: Probe,
    pub(crate) timeout: Duration,
    pub(crate) limits: Limits,
    pub(crate) permit: ExecutionPermit,
}

/// The evidence one [`Exchange`] produced, bound to its permit.
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

/// One authorized DNS-over-TCP query, direct or following validated UDP
/// truncation. It runs on a kernel socket, so it is a query, not an exchange:
/// nothing is captured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TcpQuery {
    /// Logical retry attempt, shared with UDP when this is a continuation.
    pub(crate) attempt: u32,
    /// Already-reauthorized numeric server and DNS port.
    pub(crate) endpoint: SocketAddr,
    /// Exact DNS query message without the TCP length prefix.
    pub(crate) query: Bytes,
    /// Time remaining in the bounded DNS attempt window.
    pub(crate) timeout: Duration,
    /// Maximum response message bytes allowed before allocation.
    pub(crate) max_message_bytes: usize,
    pub(crate) permit: ExecutionPermit,
}

/// The socket evidence one [`TcpQuery`] produced, bound to its permit.
#[derive(Clone, Debug)]
pub(crate) struct TcpEvidence {
    pub(crate) permit: ExecutionPermit,
    pub(crate) response: super::tcp::Response,
}

/// The DNS-over-TCP capability an executor provides next to its UDP
/// [`Executor`] implementation.
pub(crate) trait TcpQuerier {
    /// Runs one bounded DNS-over-TCP query. Expected socket and framing
    /// failures are returned as typed data so the workflow can apply its
    /// normal retry precedence.
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

impl<P: Providers, K: Clock> Executor<Exchange> for ExchangeExecutor<'_, P, K> {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        let max_responses = exchange.limits.max_evidence_frames;
        if max_responses == 0 {
            return Err(EXECUTOR_FAULT.invalid("DNS exchange must retain at least one response"));
        }
        if max_responses > self.collection.max_responses {
            return Err(EXECUTOR_FAULT.invalid(format!(
                "DNS exchange requests {} responses but the client is bounded to {}",
                max_responses, self.collection.max_responses
            )));
        }
        // Everything the client captures is DNS evidence, which must fit the
        // request's own bounds; refuse before any I/O rather than after.
        let capture = &self.collection.capture;
        if capture.max_frames > max_responses
            || capture.max_bytes > exchange.limits.max_evidence_bytes
        {
            return Err(EXECUTOR_FAULT.invalid(format!(
                "the client captures up to {} frames and {} bytes but the DNS exchange retains at most {} frames and {} bytes",
                capture.max_frames,
                capture.max_bytes,
                max_responses,
                exchange.limits.max_evidence_bytes
            )));
        }
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
        } = result;
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

/// Queries over the client's TCP provider. Kernel TCP cannot honor
/// packet-oriented route overrides, so a query refuses them before any
/// provider I/O.
impl<P: Providers, K: Clock> TcpQuerier for ExchangeExecutor<'_, P, K> {
    fn query(&mut self, query: &TcpQuery) -> Result<TcpEvidence, super::tcp::Error> {
        validate_tcp_route_options(&self.send.plan)?;
        let response = super::tcp::query(
            super::tcp::Request {
                endpoint: query.endpoint,
                query: &query.query,
                timeout: query.timeout,
                max_message_bytes: query.max_message_bytes,
            },
            self.client.providers.tcp(),
        )?;
        Ok(TcpEvidence {
            permit: query.permit,
            response,
        })
    }
}

fn validate_tcp_route_options(plan: &crate::route::Options) -> Result<(), crate::dns::tcp::Error> {
    if plan.interface.is_some()
        || plan.preferred_source.is_some()
        || !matches!(plan.link_mode, packetcraftr_netio::link::Mode::Auto)
    {
        return Err(crate::dns::tcp::Error::Unsupported {
            message: "kernel TCP cannot preserve packet-oriented interface, source, or link-mode overrides; use UDP-only DNS"
                .to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::test_support::{Call, fake_client};

    #[test]
    fn tcp_queries_the_client_provider_and_rejects_overrides_before_provider_io() {
        let (client, providers) = fake_client();
        let query = TcpQuery {
            attempt: 1,
            endpoint: "127.0.0.1:53".parse().unwrap(),
            query: Bytes::from_static(b"query"),
            timeout: Duration::from_secs(1),
            max_message_bytes: 512,
            permit: ExecutionPermit::new(),
        };
        let mut executor = ExchangeExecutor::new(
            &client,
            crate::send::Options::default(),
            crate::exchange::Collection::default(),
        );
        let error = executor.query(&query).unwrap_err();
        assert!(matches!(error, super::super::tcp::Error::Connect { .. }));
        assert_eq!(providers.calls(), [Call::Connect(query.endpoint)]);

        executor.send.plan.preferred_source = Some("192.0.2.1".parse().unwrap());
        assert!(matches!(
            executor.query(&query),
            Err(super::super::tcp::Error::Unsupported { .. })
        ));
        assert_eq!(providers.calls().len(), 1, "no second connect");
    }

    #[test]
    fn tcp_route_validation_rejects_every_packet_oriented_override() {
        let defaults = crate::route::Options::default();
        assert!(validate_tcp_route_options(&defaults).is_ok());

        let mut source = defaults.clone();
        source.preferred_source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(validate_tcp_route_options(&source).is_err());

        let mut interface = defaults.clone();
        interface.interface = Some(crate::route::Interface::Name("fixture0".to_owned()));
        assert!(validate_tcp_route_options(&interface).is_err());

        for link_mode in [
            packetcraftr_netio::link::Mode::Layer2,
            packetcraftr_netio::link::Mode::Layer3,
        ] {
            let mut plan = defaults.clone();
            plan.link_mode = link_mode;
            assert!(validate_tcp_route_options(&plan).is_err());
        }
    }
}
