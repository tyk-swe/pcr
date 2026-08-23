// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::BoundaryError;
use crate::ExchangeExecutor;
use packetcraftr_core::error::Classification;
use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

use super::boundary::{Execution, ExecutionCase, Executor};

/// Executes one generated fuzz case through the client's capture-ready
/// exchange lifecycle.
impl<R, N, I> Executor for ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(
        &mut self,
        case: &ExecutionCase,
        timeout: Duration,
    ) -> Result<Execution, BoundaryError> {
        let mut options = self.options.clone();
        options.timeout = timeout;
        options.max_template_packets = 1;
        let exchange = self
            .client
            .exchange(
                &packetcraftr_core::template::Template::new(case.packet.clone()),
                options,
            )
            .map_err(BoundaryError::from_error)?;
        let crate::exchange::Result {
            mut sent,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = exchange;
        if sent.len() != 1 {
            return Err(invalid_client_execution(format!(
                "expected one sent receipt, received {}",
                sent.len()
            )));
        }
        let sent =
            crate::exchange::into_sent_packet(sent.pop().expect("validated one sent fuzz packet"));
        Ok(Execution {
            permit: case.permit,
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
    BoundaryError::new(
        message,
        Classification::new(
            "internal.fuzz_executor",
            Some("execute exactly one bounded fuzz case per capture-ready exchange"),
        ),
        Vec::new(),
    )
}
