// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::ExchangeExecutor;
use crate::probe::client_executor::{ExecutorFault, WorkflowOverrides};

use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

use super::classification::classify_response;
use super::model::{Batch, Execution, Executor, Probe, Strategy};

const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.traceroute_executor",
    "use homogeneous bounded hop batches and retain at least one response per probe",
);

/// Executes homogeneous traceroute hop batches through the client's
/// capture-ready exchange lifecycle.
impl<R, N, I> Executor<Probe> for ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        let first = batch.probes.first().ok_or_else(|| {
            EXECUTOR_FAULT.invalid("traceroute executor received an empty hop batch")
        })?;
        if batch
            .probes
            .iter()
            .any(|probe| probe.target.port() == Some(0))
        {
            return Err(
                EXECUTOR_FAULT.invalid("traceroute probes require a non-zero destination port")
            );
        }
        if batch.probes.iter().any(|probe| {
            probe.address != first.address
                || probe.target.transport() != first.target.transport()
                || probe.hop_limit != first.hop_limit
                || (probe.target.transport() == Strategy::Tcp && probe.target != first.target)
        }) {
            return Err(EXECUTOR_FAULT.invalid(
                "traceroute batches must share address, strategy, hop limit, and TCP destination port",
            ));
        }
        if self.options.max_responses < batch.probes.len() {
            return Err(EXECUTOR_FAULT.invalid(format!(
                "max_responses={} is smaller than traceroute hop batch size {}",
                self.options.max_responses,
                batch.probes.len()
            )));
        }

        let varying_field = match first.target.transport() {
            Strategy::Udp => "destination_port",
            Strategy::Tcp => "sequence",
            Strategy::Icmp => "body",
        };
        let mut template = packetcraftr_core::template::Template::new(first.packet());
        if batch.probes.len() > 1 {
            let values = batch
                .probes
                .iter()
                .map(|probe| {
                    probe
                        .packet()
                        .iter()
                        .nth(1)
                        .and_then(|layer| layer.field(varying_field))
                        .ok_or_else(|| {
                            EXECUTOR_FAULT.invalid(format!(
                                "{} probe has no {varying_field} correlation field",
                                probe.target.transport()
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            template = template.axis(1, varying_field, values);
        }

        let mut matches_request =
            |request_index: usize,
             sent: &packetcraftr_core::Packet,
             response: &packetcraftr_core::decode::DecodedPacket| {
                batch.probes.get(request_index).is_some_and(|probe| {
                    classify_response(
                        self.client.registry(),
                        probe.target.transport(),
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
        let execution = Execution::from_exchange(batch.permit, exchange);
        Ok(execution)
    }
}
