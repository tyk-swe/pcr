// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The live fuzz executor boundary: one permit-bound case in, one bounded
//! evidence receipt out, served by a capture-ready exchange on the client.

use std::time::Duration;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::packet::Packet;

use crate::clock::Clock;
use crate::evidence::ExecutionPermit;
use crate::execution::{ExchangeExecutor, Executor, ExecutorFault, Receipt};
use crate::providers::Providers;
use packetcraftr_core::error::BoundaryError;

const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "internal.fuzz_executor",
    "execute exactly one bounded fuzz case per capture-ready exchange",
);

/// One built case, bound to the permit and clipped timeout it may run under.
#[derive(Clone, Debug)]
pub(crate) struct CaseStep {
    pub(crate) permit: ExecutionPermit,
    pub(crate) packet: Packet,
    pub(crate) timeout: Duration,
}

impl crate::execution::Step for CaseStep {
    type Evidence = CaseEvidence;
}

/// What the executor reports for one case, before the engine validates it.
#[derive(Clone, Debug)]
pub(crate) struct CaseEvidence {
    pub(crate) permit: ExecutionPermit,
    pub(crate) sent: crate::SentPacket,
    pub(crate) responses: Vec<crate::exchange::Response>,
    pub(crate) unmatched: Vec<Frame>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: crate::Stats,
}

impl Receipt for CaseEvidence {
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
    fn stats(&self) -> &crate::Stats {
        &self.stats
    }
}

impl<P: Providers, K: Clock> Executor<CaseStep> for ExchangeExecutor<'_, P, K> {
    fn execute(&mut self, case: &CaseStep) -> Result<CaseEvidence, BoundaryError> {
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
        Ok(CaseEvidence {
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
