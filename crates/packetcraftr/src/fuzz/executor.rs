// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::clock::Clock;
use crate::execution::ExchangeExecutor;
use crate::execution::Executor;
use crate::execution::ExecutorFault;
use crate::providers::Providers;

use super::execution::{Execution, ExecutionCase};

const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "internal.fuzz_executor",
    "execute exactly one bounded fuzz case per capture-ready exchange",
);

impl<P: Providers, K: Clock> Executor<ExecutionCase> for ExchangeExecutor<'_, P, K> {
    fn execute(&mut self, case: &ExecutionCase) -> Result<Execution, BoundaryError> {
        let exchange = self
            .client
            .exchange_hooked(
                crate::exchange::Request {
                    template: packetcraftr_core::template::Template::new(case.packet.clone()),
                    send: self.send.clone(),
                    timeout: case.timeout,
                    max_template_packets: 1,
                    collection: self.collection.clone(),
                },
                None,
                None,
            )
            .map_err(BoundaryError::from_error)?;
        let crate::exchange::Aggregate {
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
            responses,
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
