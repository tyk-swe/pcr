// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::ExchangeExecutor;
use crate::probe::{self, Transport as ProbeTransport};

use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

use super::model::{Exchange, Execution, Executor};

/// Executes one DNS query through the client's capture-ready exchange
/// lifecycle.
impl<R, N, I> Executor for ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(&mut self, exchange: &Exchange) -> Result<Execution, BoundaryError> {
        if exchange.max_responses == 0 {
            return Err(invalid_client_execution(
                "DNS exchange must retain at least one response",
            ));
        }
        if exchange.max_responses > self.options.max_responses {
            return Err(invalid_client_execution(format!(
                "DNS exchange requests {} responses but the client is bounded to {}",
                exchange.max_responses, self.options.max_responses
            )));
        }
        let options = crate::exchange::Options {
            max_responses: exchange.max_responses,
            max_unmatched_frames: self
                .options
                .max_unmatched_frames
                .min(exchange.max_responses),
            ..self.options.clone()
        };
        let result = ExchangeExecutor::new(self.client, options).exchange_for_workflow(
            &packetcraftr_core::template::Template::new(exchange.probe.packet()),
            exchange.timeout,
            1,
            exchange.probe.server_address,
            |_request_index, sent, response| {
                probe::observe(self.client.registry(), ProbeTransport::Udp, sent, response)
                    .is_some()
            },
        )?;
        let crate::exchange::Result {
            mut sent,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = result;
        if sent.len() != 1 {
            return Err(invalid_client_result(
                "single-query DNS exchange returned an invalid sent-evidence count",
            ));
        }
        if responses.iter().any(|response| response.request_index != 0) {
            return Err(invalid_client_result(
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

fn invalid_client_execution(message: impl Into<String>) -> BoundaryError {
    BoundaryError::execution_validation(
        message,
        "cli.dns_executor",
        "use one bounded UDP DNS query and retain at least one response",
    )
}

fn invalid_client_result(message: impl Into<String>) -> BoundaryError {
    BoundaryError::internal_execution(
        message,
        "internal.dns_executor",
        "treat the DNS operation as incomplete because client evidence was inconsistent",
    )
}
