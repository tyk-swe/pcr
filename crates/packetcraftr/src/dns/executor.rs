// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::correlation::{self, Transport as ProbeTransport};
use crate::execution::ExchangeExecutor;
use crate::execution::Executor;
use crate::execution::{ExecutorFault, WorkflowOverrides};

use crate::clock::Clock;
use crate::providers::Providers;

use super::classification::{ResponseClassification, classify_response};
use super::{Exchange, Execution, TcpExchange, TcpExecution, TcpExecutor};

const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.dns_executor",
    "use one bounded UDP DNS query and retain at least one response",
);
const RESULT_FAULT: ExecutorFault = ExecutorFault::new(
    "internal.dns_executor",
    "treat the DNS operation as incomplete because client evidence was inconsistent",
);

impl<P: Providers, K: Clock> Executor<Exchange> for ExchangeExecutor<'_, P, K> {
    fn execute(&mut self, exchange: &Exchange) -> Result<Execution, BoundaryError> {
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
        Ok(Execution {
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

/// A client exchange with an explicitly selected DNS TCP provider.
pub struct TcpExchangeExecutor<'a, P, K, T> {
    udp: ExchangeExecutor<'a, P, K>,
    tcp: T,
}

impl<'a, P, K> ExchangeExecutor<'a, P, K> {
    /// Enables direct DNS TCP queries and fallback using only the supplied provider.
    pub fn with_dns_tcp<T>(self, provider: T) -> TcpExchangeExecutor<'a, P, K, T> {
        TcpExchangeExecutor {
            udp: self,
            tcp: provider,
        }
    }
}

// A packet provider alone never implicitly selects system TCP.
impl<P, K> TcpExecutor for ExchangeExecutor<'_, P, K> {}

impl<P: Providers, K: Clock, T> Executor<Exchange> for TcpExchangeExecutor<'_, P, K, T> {
    fn execute(&mut self, exchange: &Exchange) -> Result<Execution, BoundaryError> {
        self.udp.execute(exchange)
    }
}

impl<P, K, T: packetcraftr_netio::tcp::Provider> TcpExecutor for TcpExchangeExecutor<'_, P, K, T> {
    fn execute_tcp(&mut self, exchange: &TcpExchange) -> Result<TcpExecution, super::tcp::Error> {
        validate_tcp_route_options(&self.udp.send.plan)?;
        let response = super::tcp::exchange(
            super::tcp::Request {
                endpoint: exchange.endpoint,
                query: &exchange.query,
                timeout: exchange.timeout,
                max_message_bytes: exchange.max_message_bytes,
            },
            &self.tcp,
        )?;
        Ok(TcpExecution::new(exchange.permit, response))
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

    use super::validate_tcp_route_options;

    use packetcraftr_core::budget::Deadline;

    struct RefusingTcp(std::sync::atomic::AtomicUsize);

    impl packetcraftr_netio::tcp::Provider for RefusingTcp {
        type Stream = packetcraftr_netio::tcp::SystemStream;

        fn connect(
            &self,
            endpoint: std::net::SocketAddr,
            deadline: &Deadline,
        ) -> Result<Self::Stream, packetcraftr_netio::tcp::Error> {
            let timeout = deadline.remaining().unwrap_or_default();
            assert_eq!(endpoint, "127.0.0.1:53".parse().unwrap());
            assert!(!timeout.is_zero());
            assert!(timeout <= std::time::Duration::from_secs(1));
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "injected TCP refusal",
            )
            .into())
        }
    }

    #[test]
    fn tcp_requires_explicit_composition_and_rejects_overrides_before_provider_io() {
        use super::*;
        let (client, _providers) = crate::test_support::fake_client();
        let exchange = TcpExchange {
            attempt: 1,
            endpoint: "127.0.0.1:53".parse().unwrap(),
            query: bytes::Bytes::from_static(b"query"),
            timeout: std::time::Duration::from_secs(1),
            max_message_bytes: 512,
            permit: crate::evidence::ExecutionPermit::new(),
        };
        let mut bare = ExchangeExecutor::new(
            &client,
            crate::send::Options::default(),
            crate::exchange::Collection::default(),
        );
        assert!(matches!(
            bare.execute_tcp(&exchange),
            Err(super::super::tcp::Error::Unsupported { .. })
        ));
        let mut explicit = bare.with_dns_tcp(RefusingTcp(std::sync::atomic::AtomicUsize::new(0)));
        let error = explicit.execute_tcp(&exchange).unwrap_err();
        assert!(matches!(error, super::super::tcp::Error::Connect { .. }));
        assert_eq!(explicit.tcp.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        explicit.udp.send.plan.preferred_source = Some("192.0.2.1".parse().unwrap());
        assert!(matches!(
            explicit.execute_tcp(&exchange),
            Err(super::super::tcp::Error::Unsupported { .. })
        ));
        assert_eq!(explicit.tcp.0.load(std::sync::atomic::Ordering::SeqCst), 1);
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
