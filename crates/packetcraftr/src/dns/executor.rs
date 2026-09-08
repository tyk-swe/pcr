// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::probe::ExchangeExecutor;
use crate::probe::executor::{ExecutorFault, WorkflowOverrides};
use crate::probe::{self, Executor, Transport as ProbeTransport};

use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

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

/// Executes one DNS query through the client's capture-ready exchange
/// lifecycle.
impl<R, N, I> Executor<Exchange> for ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(&mut self, exchange: &Exchange) -> Result<Execution, BoundaryError> {
        let max_responses = exchange.limits.max_evidence_frames;
        if max_responses == 0 {
            return Err(EXECUTOR_FAULT.invalid("DNS exchange must retain at least one response"));
        }
        if max_responses > self.options.max_responses {
            return Err(EXECUTOR_FAULT.invalid(format!(
                "DNS exchange requests {} responses but the client is bounded to {}",
                max_responses, self.options.max_responses
            )));
        }
        let registry = std::sync::Arc::clone(self.client.registry());
        let stop_probe = exchange.probe.clone();
        let stop_limits = exchange.limits.message;
        let mut matches_request =
            |_request_index: usize,
             sent: &packetcraftr_core::Packet,
             response: &packetcraftr_core::decode::DecodedPacket| {
                probe::observe(self.client.registry(), ProbeTransport::Udp, sent, response)
                    .is_some()
            };
        let mut stop_after_response =
            |_request_index: usize,
             sent: &packetcraftr_core::Packet,
             response: &packetcraftr_core::decode::DecodedPacket| {
                matches!(
                    classify_response(&registry, &stop_probe, sent, response, stop_limits),
                    Some(ResponseClassification::Response(_))
                )
            };
        let result = self.exchange_for_workflow(
            &packetcraftr_core::template::Template::new(exchange.probe.packet()),
            WorkflowOverrides {
                timeout: exchange.timeout,
                max_template_packets: 1,
                destination: exchange.probe.server_address,
                max_responses: Some(max_responses),
            },
            &mut matches_request,
            Some(&mut stop_after_response),
        )?;
        let crate::exchange::Report {
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
pub struct TcpExchangeExecutor<'a, R, N, I, P> {
    udp: ExchangeExecutor<'a, R, N, I>,
    tcp: P,
}

impl<'a, R, N, I> ExchangeExecutor<'a, R, N, I> {
    /// Enables DNS TCP fallback using only the supplied provider.
    pub fn with_dns_tcp<P>(self, provider: P) -> TcpExchangeExecutor<'a, R, N, I, P> {
        TcpExchangeExecutor {
            udp: self,
            tcp: provider,
        }
    }
}

// A packet provider alone never implicitly selects system TCP.
impl<R, N, I> TcpExecutor for ExchangeExecutor<'_, R, N, I> {}

impl<R, N, I, P> Executor<Exchange> for TcpExchangeExecutor<'_, R, N, I, P>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(&mut self, exchange: &Exchange) -> Result<Execution, BoundaryError> {
        self.udp.execute(exchange)
    }
}

impl<R, N, I, P: packetcraftr_netio::tcp::Provider> TcpExecutor
    for TcpExchangeExecutor<'_, R, N, I, P>
{
    fn execute_tcp(&mut self, exchange: &TcpExchange) -> Result<TcpExecution, super::tcp::Error> {
        validate_tcp_route_options(&self.udp.options.send.plan)?;
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

fn validate_tcp_route_options(
    plan: &packetcraftr_netio::route::Options,
) -> Result<(), crate::dns::tcp::Error> {
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

    struct RefusingTcp(std::cell::Cell<usize>);

    impl packetcraftr_netio::tcp::Provider for RefusingTcp {
        type Stream = packetcraftr_netio::tcp::SystemStream;

        fn connect(
            &self,
            endpoint: std::net::SocketAddr,
            timeout: std::time::Duration,
        ) -> std::io::Result<Self::Stream> {
            assert_eq!(endpoint, "127.0.0.1:53".parse().unwrap());
            assert!(!timeout.is_zero());
            assert!(timeout <= std::time::Duration::from_secs(1));
            self.0.set(self.0.get() + 1);
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "injected TCP refusal",
            ))
        }
    }

    #[test]
    fn tcp_requires_explicit_composition_and_rejects_overrides_before_provider_io() {
        use super::*;
        let client = crate::Client {
            registry: packetcraftr_core::protocol::builtin::registry(),
            routes: (),
            neighbors: (),
            io: (),
            policy: std::sync::Arc::new(crate::policy::Policy::default()),
            runtime: crate::progress::Runtime::default(),
            cancellation: None,
        };
        let exchange = TcpExchange {
            attempt: 1,
            endpoint: "127.0.0.1:53".parse().unwrap(),
            query: bytes::Bytes::from_static(b"query"),
            timeout: std::time::Duration::from_secs(1),
            max_message_bytes: 512,
            permit: crate::evidence::ExecutionPermit::new(),
        };
        let mut bare = ExchangeExecutor::new(&client, crate::exchange::Options::default());
        assert!(matches!(
            bare.execute_tcp(&exchange),
            Err(super::super::tcp::Error::Unsupported { .. })
        ));
        let mut explicit = bare.with_dns_tcp(RefusingTcp(std::cell::Cell::new(0)));
        let error = explicit.execute_tcp(&exchange).unwrap_err();
        assert!(matches!(error, super::super::tcp::Error::Connect { .. }));
        assert_eq!(explicit.tcp.0.get(), 1);
        explicit.udp.options.send.plan.preferred_source = Some("192.0.2.1".parse().unwrap());
        assert!(matches!(
            explicit.execute_tcp(&exchange),
            Err(super::super::tcp::Error::Unsupported { .. })
        ));
        assert_eq!(explicit.tcp.0.get(), 1);
    }

    #[test]
    fn tcp_route_validation_rejects_every_packet_oriented_override() {
        let defaults = packetcraftr_netio::route::Options::default();
        assert!(validate_tcp_route_options(&defaults).is_ok());

        let mut source = defaults.clone();
        source.preferred_source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(validate_tcp_route_options(&source).is_err());

        let mut interface = defaults.clone();
        interface.interface = Some(packetcraftr_netio::interface::Id {
            name: "fixture0".to_owned(),
            index: 1,
        });
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
