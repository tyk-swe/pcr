// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::BoundaryError;
use crate::ExchangeExecutor;
use packetcraftr_network::{
    capture::Provider as CaptureProvider, neighbor::Resolver as NeighborResolver,
    route::Provider as RouteProvider, transmit::Sender as PacketIo,
};
use packetcraftr_packet::template::Template as PacketTemplate;

use super::classification::classify_traceroute_response;
use super::model::{
    TracerouteBatch, TracerouteBatchExecution, TracerouteExecutor, TracerouteMatchedResponse,
    TracerouteStrategy,
};

/// Executes homogeneous traceroute hop batches through the client's
/// capture-ready exchange lifecycle.
impl<R, N, I> TracerouteExecutor for ExchangeExecutor<'_, R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, BoundaryError> {
        let first = batch.probes.first().ok_or_else(|| {
            invalid_client_execution("traceroute executor received an empty hop batch")
        })?;
        if batch
            .probes
            .iter()
            .any(|probe| !match (probe.strategy, probe.destination_port) {
                (TracerouteStrategy::Udp | TracerouteStrategy::Tcp, Some(port)) => port != 0,
                (TracerouteStrategy::Icmp, None) => true,
                _ => false,
            })
        {
            return Err(invalid_client_execution(
                "traceroute probe strategy and destination port are inconsistent",
            ));
        }
        if batch.probes.iter().any(|probe| {
            probe.address != first.address
                || probe.strategy != first.strategy
                || probe.hop_limit != first.hop_limit
                || (probe.strategy == TracerouteStrategy::Tcp
                    && probe.destination_port != first.destination_port)
        }) {
            return Err(invalid_client_execution(
                "traceroute batches must share address, strategy, hop limit, and TCP destination port",
            ));
        }
        if self.options.max_responses < batch.probes.len() {
            return Err(invalid_client_execution(format!(
                "max_responses={} is smaller than traceroute hop batch size {}",
                self.options.max_responses,
                batch.probes.len()
            )));
        }

        let varying_field = match first.strategy {
            TracerouteStrategy::Udp => "destination_port",
            TracerouteStrategy::Tcp => "sequence",
            TracerouteStrategy::Icmp => "body",
        };
        let mut template = PacketTemplate::new(first.packet());
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
                            invalid_client_execution(format!(
                                "{} probe has no {varying_field} correlation field",
                                probe.strategy
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            template = template.axis(1, varying_field, values);
        }

        let mut options = self.options.clone();
        options.timeout = batch.timeout;
        options.max_template_packets = batch.probes.len();
        options.send.destination = Some(first.address);
        let exchange = self
            .client
            .exchange_for_workflow(&template, options, |request_index, sent, response| {
                batch.probes.get(request_index).is_some_and(|probe| {
                    classify_traceroute_response(
                        self.client.registry(),
                        probe.strategy,
                        sent,
                        response,
                    )
                    .is_some()
                })
            })
            .map_err(BoundaryError::from_error)?;
        let crate::exchange::Result {
            sent,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = exchange;
        Ok(TracerouteBatchExecution {
            permit: batch.permit,
            sent,
            responses: responses
                .into_iter()
                .map(|response| TracerouteMatchedResponse {
                    request_index: response.request_index,
                    response: response.response,
                    latency: response.latency,
                })
                .collect(),
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        })
    }
}

fn invalid_client_execution(message: impl Into<String>) -> BoundaryError {
    BoundaryError::execution_validation(
        message,
        "cli.traceroute_executor",
        "use homogeneous bounded hop batches and retain at least one response per probe",
    )
}
