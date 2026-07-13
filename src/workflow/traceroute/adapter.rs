/// Executes homogeneous traceroute hop batches through the client's
/// capture-ready exchange lifecycle.
pub struct ClientExecutor<'a, R, N, I> {
    client: &'a crate::client::Client<R, N, I>,
    options: crate::client::exchange::Options,
    capture_options: crate::net::capture::Options,
    operation: Option<crate::operation::Context>,
}

impl<'a, R, N, I> ClientExecutor<'a, R, N, I> {
    pub fn new(
        client: &'a crate::client::Client<R, N, I>,
        options: crate::client::exchange::Options,
    ) -> Self {
        Self {
            client,
            options,
            capture_options: crate::net::capture::Options::default(),
            operation: None,
        }
    }

    pub fn with_capture_options(mut self, options: crate::net::capture::Options) -> Self {
        self.capture_options = options;
        self
    }

    pub fn with_operation_context(mut self, operation: crate::operation::Context) -> Self {
        self.operation = Some(operation);
        self
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
        if batch.probes.iter().any(|probe| {
            probe.address != first.address
                || probe.strategy != first.strategy
                || probe.hop_limit != first.hop_limit
        }) {
            return Err(invalid_client_execution(
                "traceroute batches must share address, strategy, and hop limit",
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
            let values = |layer: usize, field: &'static str| {
                batch
                    .probes
                    .iter()
                    .map(|probe| {
                        probe
                            .packet()
                            .iter()
                            .nth(layer)
                            .and_then(|packet_layer| packet_layer.field(field))
                            .ok_or_else(|| {
                                invalid_client_execution(format!(
                                    "{} probe has no {field} correlation field",
                                    probe.strategy
                                ))
                            })
                    })
                    .collect::<Result<Vec<FieldValue>, _>>()
            };
            let network_field = if first.address.is_ipv4() {
                "identification"
            } else {
                "flow_label"
            };
            template = template.zip_axes([
                (
                    0,
                    network_field,
                    TemplateValues::Values(values(0, network_field)?),
                ),
                (
                    1,
                    varying_field,
                    TemplateValues::Values(values(1, varying_field)?),
                ),
            ]);
        }

        let mut options = self.options.clone();
        options.timeout = batch.timeout;
        options.max_template_packets = batch.probes.len();
        options.send.destination = Some(first.address);
        let exchange = match &self.operation {
            Some(operation) => self.client.exchange_streaming(
                &template,
                options,
                self.capture_options.clone(),
                operation,
                &mut |_| Ok(()),
            ),
            None => self.client.exchange_with_capture_options(
                &template,
                options,
                self.capture_options.clone(),
            ),
        }
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
            stats: stats.into(),
        })
    }
}

fn invalid_client_execution(message: impl Into<String>) -> TracerouteExecutionError {
    TracerouteExecutionError::new(
        message,
        Classification::new(
            "cli.traceroute_executor",
            Kind::Cli,
            Some("use homogeneous bounded hop batches and retain at least one response per probe"),
        ),
        Vec::new(),
    )
}
