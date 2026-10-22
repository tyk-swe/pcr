// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::engine::execution::Executor;
use crate::engine::execution::ExecutorFault;
use crate::exchange::WorkflowExecutor;
use crate::exchange::WorkflowOverrides;
use crate::probe::{Batch, Evidence, Transport};
use packetcraftr_core::error::BoundaryError;

use crate::clock::Clock;
use crate::providers::PacketProviders;

use super::Probe;
use super::evidence::classify_response;

const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.traceroute_executor",
    "use homogeneous bounded hop batches and retain at least one response per probe",
);

impl<P: PacketProviders, K: Clock> Executor<Batch<Probe>> for WorkflowExecutor<'_, P, K> {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let first = validate_batch(batch)?;

        let varying_field = match first.target.transport() {
            Transport::Udp => "destination_port",
            Transport::Tcp => "sequence",
            Transport::Icmp => "body",
            Transport::Sctp | Transport::Ip => {
                return Err(EXECUTOR_FAULT.invalid("unsupported traceroute strategy"));
            }
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
             sent: &packetcraftr_core::packet::Packet,
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
            template,
            WorkflowOverrides {
                timeout: batch.timeout,
                max_template_packets: batch.probes.len(),
                destination: first.address,
                interface: None,
                max_responses: None,
            },
            &mut matches_request,
            None,
        )?;
        let execution = Evidence::from_exchange(batch.permit, exchange);
        Ok(execution)
    }
}

fn validate_batch(batch: &Batch<Probe>) -> Result<&Probe, BoundaryError> {
    let first = batch
        .probes
        .first()
        .ok_or_else(|| EXECUTOR_FAULT.invalid("traceroute executor received an empty hop batch"))?;
    if batch
        .probes
        .iter()
        .any(|probe| probe.target.port() == Some(0))
    {
        return Err(EXECUTOR_FAULT.invalid("traceroute probes require a non-zero destination port"));
    }
    if batch
        .probes
        .iter()
        .any(|probe| probe.target.transport() != Transport::Icmp && probe.source_port == 0)
    {
        return Err(
            EXECUTOR_FAULT.invalid("UDP and TCP traceroute probes require a non-zero source port")
        );
    }
    if batch.probes.iter().any(|probe| {
        probe.address != first.address
            || probe.target.transport() != first.target.transport()
            || probe.source_port != first.source_port
            || probe.payload_size != first.payload_size
            || probe.dont_fragment != first.dont_fragment
            || probe.dscp != first.dscp
            || probe.hop_limit != first.hop_limit
            || (probe.target.transport() == Transport::Tcp && probe.target != first.target)
    }) {
        return Err(EXECUTOR_FAULT.invalid(
            "traceroute batches must share address, strategy, source port, probe shape, hop limit, and TCP destination port",
        ));
    }
    Ok(first)
}
