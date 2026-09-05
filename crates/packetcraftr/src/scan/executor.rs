// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::probe::ExchangeExecutor;
use crate::probe::executor::{ExecutorFault, WorkflowOverrides};
use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

use super::classification::classify_response;
use super::model::{Batch, Execution, Executor};

const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.scan_executor",
    "use one correlated probe per scan batch and retain at least one response",
);

/// Executes single-probe scan batches through the client's capture-ready
/// exchange lifecycle.
impl<R, N, I> Executor<Batch> for ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let first = batch
            .probes
            .first()
            .ok_or_else(|| EXECUTOR_FAULT.invalid("scan executor received an empty batch"))?;
        if batch.probes.len() != 1 {
            return Err(EXECUTOR_FAULT.invalid("scan batches require exactly one correlated probe"));
        }
        if self.options.max_responses < batch.probes.len() {
            return Err(EXECUTOR_FAULT.invalid(format!(
                "max_responses={} is smaller than scan batch size {}",
                self.options.max_responses,
                batch.probes.len()
            )));
        }

        let packet = first.packet();
        if !super::probe::sent_probe_matches(first, &packet) {
            return Err(EXECUTOR_FAULT.invalid("scan packet does not match its correlated probe"));
        }
        let template = packetcraftr_core::template::Template::new(packet);
        let mut matches_request =
            |request_index: usize,
             sent: &packetcraftr_core::Packet,
             response: &packetcraftr_core::decode::DecodedPacket| {
                batch.probes.get(request_index).is_some_and(|probe| {
                    classify_response(
                        self.client.registry(),
                        probe.endpoint.transport(),
                        sent,
                        response,
                    )
                    .is_some()
                })
            };
        let exchange = self.exchange_for_workflow(
            &template,
            WorkflowOverrides {
                timeout: batch.timeout,
                max_template_packets: batch.probes.len(),
                destination: first.address,
                max_responses: None,
            },
            &mut matches_request,
            None,
        )?;
        Ok(Execution::from_exchange(batch.permit, exchange))
    }
}
