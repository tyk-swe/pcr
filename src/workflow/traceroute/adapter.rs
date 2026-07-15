/// Executes homogeneous traceroute hop batches through the client's
/// capture-ready exchange lifecycle.
pub struct ClientExecutor<'a, R, N, I> {
    client: &'a crate::client::Client<R, N, I>,
    options: crate::client::exchange::Options,
}

impl<'a, R, N, I> ClientExecutor<'a, R, N, I> {
    pub fn new(
        client: &'a crate::client::Client<R, N, I>,
        options: crate::client::exchange::Options,
    ) -> Self {
        Self { client, options }
    }
}

impl<R, N, I> TracerouteExecutor for ClientExecutor<'_, R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: ExchangeIo,
{
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, TracerouteExecutionError> {
        let Some(first) = batch.probes.first() else {
            return Err(invalid_client_execution(
                "traceroute executor received an empty hop batch",
            ));
        };
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
        let first_packet = first.packet();
        let mut template = PacketTemplate::new(first_packet);
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
            template = template.axis(1, varying_field, TemplateValues::Values(values));
        }

        let mut options = self.options.clone();
        options.timeout = batch.timeout;
        options.max_template_packets = batch.probes.len();
        options.send.destination = Some(first.address);
        let exchange = self
            .client
            .exchange(&template, options)
            .map_err(|error| TracerouteExecutionError::classified(&error))?;
        let crate::client::exchange::Result {
            sent,
            sent_evidence,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = exchange;
        Ok(TracerouteBatchExecution {
            sent: sent.into_iter().map(|built| built.packet).collect(),
            sent_evidence,
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

fn invalid_client_execution(message: impl Into<String>) -> TracerouteExecutionError {
    TracerouteExecutionError::execution_validation(
        message,
        "cli.traceroute_executor",
        "use homogeneous bounded hop batches and retain at least one response per probe",
    )
}
use super::{
    ExchangeIo, NeighborResolver, PacketTemplate, RouteProvider, TemplateValues, TracerouteBatch,
    TracerouteBatchExecution, TracerouteExecutionError, TracerouteExecutor,
    TracerouteMatchedResponse, TracerouteStrategy,
};
