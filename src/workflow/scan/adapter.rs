/// Executes homogeneous scan batches through the client's capture-ready
/// exchange lifecycle.
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
            template = template.axis(1, "destination_port", TemplateValues::Values(ports));
        }
        let mut options = self.options.clone();
        options.timeout = batch.timeout;
        options.max_template_packets = batch.probes.len();
        options.send.destination = Some(first.address);
        let exchange = self
            .client
            .exchange(&template, options)
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
            stats: Stats {
                packets_attempted: stats.packets_attempted,
                packets_completed: stats.packets_completed,
                bytes: stats.bytes,
                elapsed: stats.elapsed,
                capture: stats.capture,
            },
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
