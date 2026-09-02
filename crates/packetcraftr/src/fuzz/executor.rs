// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::ExchangeExecutor;
use crate::probe::Executor;
use crate::probe::executor::ExecutorFault;
use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

use super::execution::{Execution, ExecutionCase};

const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "internal.fuzz_executor",
    "execute exactly one bounded fuzz case per capture-ready exchange",
);

/// Executes one generated fuzz case through the client's capture-ready
/// exchange lifecycle.
impl<R, N, I> Executor<ExecutionCase> for ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(&mut self, case: &ExecutionCase) -> Result<Execution, BoundaryError> {
        let mut options = self.options.clone();
        options.timeout = case.timeout;
        options.max_template_packets = 1;
        let exchange = self
            .client
            .exchange(
                &packetcraftr_core::template::Template::new(case.packet.clone()),
                options,
            )
            .map_err(BoundaryError::from_error)?;
        let crate::exchange::Report {
            sent,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = exchange;
        let sent = match <[_; 1]>::try_from(sent) {
            Ok([sent]) => crate::exchange::into_sent_packet(sent),
            Err(sent) => {
                return Err(EXECUTOR_FAULT.internal(format!(
                    "expected one sent receipt, received {}",
                    sent.len()
                )));
            }
        };
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
