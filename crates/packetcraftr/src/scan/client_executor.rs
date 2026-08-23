// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::ExchangeExecutor;
use packetcraftr_core::error::Classification;
use packetcraftr_core::field::FieldValue;
use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

use super::classification::classify_response;
use super::model::{Batch, Execution, Executor, Transport};

/// Executes homogeneous scan batches through the client's capture-ready
/// exchange lifecycle.
impl<R, N, I> Executor for ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let first = batch
            .probes
            .first()
            .ok_or_else(|| invalid_client_execution("scan executor received an empty batch"))?;
        if batch.probes.iter().any(|probe| {
            probe.address != first.address
                || probe.transport != first.transport
                || probe.attempt != first.attempt
        }) {
            return Err(invalid_client_execution(
                "scan executor batches must share address, transport, and attempt",
            ));
        }
        if first.transport == Transport::Icmp && batch.probes.len() != 1 {
            return Err(invalid_client_execution(
                "ICMP batches must contain exactly one uniquely identified echo probe",
            ));
        }
        if self.options.max_responses < batch.probes.len() {
            return Err(invalid_client_execution(format!(
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
                        .port
                        .map(|port| FieldValue::Unsigned(u64::from(port)))
                        .ok_or_else(|| {
                            invalid_client_execution(
                                "portless probes cannot form a multi-packet batch",
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            template = template.axis(1, "destination_port", ports);
        }
        let exchange = self.exchange_for_workflow(
            &template,
            batch.timeout,
            batch.probes.len(),
            first.address,
            |request_index, sent, response| {
                batch.probes.get(request_index).is_some_and(|probe| {
                    classify_response(self.client.registry(), probe.transport, sent, response)
                        .is_some()
                })
            },
        )?;
        Ok(Execution::from_exchange(batch.permit, exchange))
    }
}

fn invalid_client_execution(message: impl Into<String>) -> BoundaryError {
    BoundaryError::new(
        message,
        Classification::new(
            "cli.scan_executor",
            Some("use homogeneous bounded scan batches and retain at least one response per probe"),
        ),
        Vec::new(),
    )
}
