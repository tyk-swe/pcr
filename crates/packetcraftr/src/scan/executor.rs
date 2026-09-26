// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::clock::Clock;
use crate::execution::{ExchangeExecutor, Executor, PipelineEvent, PipelineOptions};
use crate::execution::{ExecutorFault, WorkflowOverrides};
use crate::probe::Execution;
use crate::providers::Providers;

use super::Batch;
use super::classification::classify_response;

pub(super) mod pipeline;
pub(super) mod registry;

pub(super) const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.scan_executor",
    "use one correlated probe per scan batch and retain at least one response",
);

impl<P: Providers, K: Clock> Executor<Batch> for ExchangeExecutor<'_, P, K> {
    fn pipeline_capacity(&self) -> usize {
        1024
    }
    fn execute_pipeline(
        &mut self,
        requests: &[Batch],
        options: PipelineOptions,
        emit: &mut dyn FnMut(PipelineEvent<Execution>) -> Result<(), BoundaryError>,
    ) -> Result<crate::Stats, BoundaryError> {
        let registry = super::executor::registry::configured(self.client.registry(), requests)?;
        let client = self.client.view_with_registry(registry);
        super::executor::pipeline::run(
            &mut ExchangeExecutor::new(&client, self.send.clone(), self.collection.clone()),
            requests,
            options,
            emit,
        )
    }
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let registry = super::executor::registry::configured(
            self.client.registry(),
            std::slice::from_ref(batch),
        )?;
        let client = self.client.view_with_registry(registry);
        let executor = ExchangeExecutor::new(&client, self.send.clone(), self.collection.clone());
        let first = batch.probe()?;
        let packet = first.packet();
        if !super::plan::packet::sent_probe_matches(first, &packet) {
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
            template,
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
