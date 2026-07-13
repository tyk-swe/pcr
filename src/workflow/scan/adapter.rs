/// Executes homogeneous scan batches through the client's capture-ready
/// exchange lifecycle.
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

impl<R, N, I> ScanExecutor for ClientExecutor<'_, R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: ExchangeIo,
{
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError> {
        let Some(first) = batch.probes.first() else {
            return Err(invalid_client_execution(
                "scan executor received an empty batch",
            ));
        };
        if batch.probes.iter().any(|probe| {
            probe.address != first.address
                || probe.transport != first.transport
                || probe.attempt != first.attempt
        }) {
            return Err(invalid_client_execution(
                "scan executor batches must share address, transport, and attempt",
            ));
        }
        if first.transport == ScanTransport::Icmp && batch.probes.len() != 1 {
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

        let mut template = PacketTemplate::new(first.packet());
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
                                    probe.transport
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
            let mut axes = vec![(
                0,
                network_field,
                TemplateValues::Values(values(0, network_field)?),
            )];
            axes.push((
                1,
                "destination_port",
                TemplateValues::Values(values(1, "destination_port")?),
            ));
            if first.transport == ScanTransport::Tcp {
                axes.push((
                    1,
                    "sequence",
                    TemplateValues::Values(values(1, "sequence")?),
                ));
            }
            template = template.zip_axes(axes);
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
        .map_err(|error| ScanExecutionError::classified(&error))?;
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
        Ok(ScanBatchExecution {
            sent: sent.into_iter().map(|built| built.packet).collect(),
            sent_evidence,
            responses: responses
                .into_iter()
                .map(|response| ScanMatchedResponse {
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

fn invalid_client_execution(message: impl Into<String>) -> ScanExecutionError {
    ScanExecutionError::new(
        message,
        Classification::new(
            "cli.scan_executor",
            Kind::Cli,
            Some("use homogeneous bounded scan batches and retain at least one response per probe"),
        ),
        Vec::new(),
    )
}
