// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Executes generated fuzz cases through the client's capture-ready exchange.

use std::time::Duration;

use packetcraftr_client::Client;
use packetcraftr_client::exchange::Options as ExchangeOptions;
use packetcraftr_net::capture::CaptureProvider;
use packetcraftr_net::route::{NeighborResolver, RouteProvider};
use packetcraftr_net::transmit::PacketIo;
use packetcraftr_packet::template::PacketTemplate;
use packetcraftr_workflow::BoundaryError;
use packetcraftr_workflow::fuzz::{
    Execution as FuzzCaseExecution, ExecutionCase as FuzzExecutionCase, Executor as FuzzExecutor,
};

/// Executes one generated fuzz case through the client's capture-ready
/// exchange lifecycle.
pub struct ClientExecutor<'a, R, N, I> {
    client: &'a Client<R, N, I>,
    options: ExchangeOptions,
}

impl<'a, R, N, I> ClientExecutor<'a, R, N, I> {
    pub fn new(client: &'a Client<R, N, I>, options: ExchangeOptions) -> Self {
        Self { client, options }
    }
}

impl<R, N, I> FuzzExecutor for ClientExecutor<'_, R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(
        &mut self,
        case: &FuzzExecutionCase,
        timeout: Duration,
    ) -> Result<FuzzCaseExecution, BoundaryError> {
        let mut options = self.options.clone();
        options.timeout = timeout;
        options.max_template_packets = 1;
        let exchange = self
            .client
            .exchange(&PacketTemplate::new(case.packet.clone()), options)
            .map_err(BoundaryError::from_error)?;
        let packetcraftr_client::exchange::Result {
            mut sent,
            mut sent_evidence,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = exchange;
        if sent.len() != 1 || sent_evidence.len() != 1 {
            return Err(invalid_client_execution(format!(
                "expected one built and sent frame, received {} built and {} sent",
                sent.len(),
                sent_evidence.len()
            )));
        }
        let built = sent.pop().expect("validated one built fuzz packet");
        let sent = sent_evidence.pop().expect("validated one sent fuzz frame");
        Ok(FuzzCaseExecution {
            built,
            sent,
            responses: responses
                .into_iter()
                .map(|response| response.response.frame)
                .collect(),
            unmatched: unsolicited
                .into_iter()
                .map(|response| response.frame)
                .collect(),
            undecoded,
            diagnostics,
            stats,
        })
    }
}

fn invalid_client_execution(message: impl Into<String>) -> BoundaryError {
    BoundaryError::internal_execution(
        message,
        "internal.fuzz_executor",
        "execute exactly one bounded fuzz case per capture-ready exchange",
    )
}
