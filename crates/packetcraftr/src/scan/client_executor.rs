// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::ExchangeExecutor;
use crate::probe::client_executor::{ExecutorFault, WorkflowOverrides};
use packetcraftr_core::field::FieldValue;
use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

use super::classification::classify_response;
use super::model::{Batch, Execution, Executor, Probe, Transport};

const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.scan_executor",
    "use homogeneous bounded scan batches and retain at least one response per probe",
);

/// Executes homogeneous scan batches through the client's capture-ready
/// exchange lifecycle.
impl<R, N, I> Executor<Probe> for ExchangeExecutor<'_, R, N, I>
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
        if batch.probes.iter().any(|probe| {
            probe.address != first.address
                || probe.endpoint.transport() != first.endpoint.transport()
                || probe.attempt != first.attempt
        }) {
            return Err(EXECUTOR_FAULT
                .invalid("scan executor batches must share address, transport, and attempt"));
        }
        if first.endpoint.transport() == Transport::Icmp && batch.probes.len() != 1 {
            return Err(EXECUTOR_FAULT
                .invalid("ICMP batches must contain exactly one uniquely identified echo probe"));
        }
        if self.options.max_responses < batch.probes.len() {
            return Err(EXECUTOR_FAULT.invalid(format!(
                "max_responses={} is smaller than scan batch size {}",
                self.options.max_responses,
                batch.probes.len()
            )));
        }

        let mut template = packetcraftr_core::template::Template::new(first.packet());
        if batch.probes.len() > 1 {
            let ports = batch
                .probes
                .iter()
                .map(|probe| {
                    probe
                        .endpoint
                        .port()
                        .map(|port| FieldValue::Unsigned(u64::from(port)))
                        .ok_or_else(|| {
                            EXECUTOR_FAULT
                                .invalid("portless probes cannot form a multi-packet batch")
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            template = template.axis(1, "destination_port", ports);
        }
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
