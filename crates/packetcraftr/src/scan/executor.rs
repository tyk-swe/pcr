// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::probe::executor::{ExecutorFault, WorkflowOverrides};
use crate::probe::{ExchangeExecutor, Execution, Executor};
use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

use super::Batch;
use super::classification::classify_response;

const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.scan_executor",
    "use one correlated probe per scan batch and retain at least one response",
);

impl<R, N, I> Executor<Batch> for ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo + CaptureProvider,
{
    fn pipeline_capacity(&self) -> usize {
        1024
    }
    fn execute_pipeline(
        &mut self,
        requests: &[Batch],
        options: crate::probe::PipelineOptions,
        emit: &mut dyn FnMut(crate::probe::PipelineEvent<Execution>) -> Result<(), BoundaryError>,
    ) -> Result<crate::Stats, BoundaryError> {
        let registry = super::registry::configured(self.client.registry(), requests)?;
        let client = super::registry::client(self.client, registry);
        super::pipeline::run(
            &mut ExchangeExecutor::new(&client, self.options.clone()),
            requests,
            options,
            emit,
        )
    }
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let registry =
            super::registry::configured(self.client.registry(), std::slice::from_ref(batch))?;
        let client = super::registry::client(self.client, registry);
        let executor = ExchangeExecutor::new(&client, self.options.clone());
        let first = &batch.probe;
        let packet = first.packet();
        if !super::probe::sent_probe_matches(first, &packet) {
            return Err(EXECUTOR_FAULT.invalid("scan packet does not match its correlated probe"));
        }
        let template = packetcraftr_core::template::Template::new(packet);
        let mut matches_request =
            |request_index: usize,
             sent: &packetcraftr_core::packet::Packet,
             response: &packetcraftr_core::decode::DecodedPacket| {
                request_index == 0
                    && classify_response(
                        executor.client.registry(),
                        first.endpoint.transport(),
                        sent,
                        response,
                    )
                    .is_some()
            };
        let exchange = executor.exchange_for_workflow(
            &template,
            WorkflowOverrides {
                timeout: batch.timeout,
                max_template_packets: 1,
                destination: first.address,
                max_responses: None,
            },
            &mut matches_request,
            None,
        )?;
        Ok(Execution::from_exchange(batch.permit, exchange))
    }
}
