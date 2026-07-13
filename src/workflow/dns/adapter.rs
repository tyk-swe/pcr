/// Executes one DNS query through the client's capture-ready exchange
/// lifecycle.
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

impl<R, N, I> DnsExecutor for ClientExecutor<'_, R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: ExchangeIo,
{
    fn execute(
        &mut self,
        exchange: &DnsExchange,
    ) -> Result<DnsExchangeExecution, DnsExecutionError> {
        if exchange.max_responses == 0 {
            return Err(invalid_client_execution(
                "DNS exchange must retain at least one response",
            ));
        }
        if exchange.max_responses > self.options.max_responses {
            return Err(invalid_client_execution(format!(
                "DNS exchange requests {} responses but the client is bounded to {}",
                exchange.max_responses, self.options.max_responses
            )));
        }
        let mut options = self.options.clone();
        options.timeout = exchange.timeout;
        options.max_template_packets = 1;
        options.max_responses = exchange.max_responses;
        options.max_unsolicited = options.max_unsolicited.min(exchange.max_responses);
        options.send.destination = Some(exchange.probe.server_address);
        let result = self
            .client
            .exchange(&PacketTemplate::new(exchange.probe.packet()), options)
            .map_err(|error| DnsExecutionError::classified(&error))?;
        let crate::client::exchange::Result {
            mut sent,
            mut sent_evidence,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = result;
        if sent.len() != 1 || sent_evidence.len() != 1 {
            return Err(invalid_client_execution(
                "single-query DNS exchange returned an invalid sent-evidence count",
            ));
        }
        if responses.iter().any(|response| response.request_index != 0) {
            return Err(invalid_client_execution(
                "single-query DNS exchange returned a response for an unknown request index",
            ));
        }
        Ok(DnsExchangeExecution {
            sent: sent.pop().expect("validated one sent packet").packet,
            sent_evidence: sent_evidence
                .pop()
                .expect("validated one sent evidence frame"),
            responses: responses
                .into_iter()
                .map(|response| DnsMatchedResponse {
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

fn invalid_client_execution(message: impl Into<String>) -> DnsExecutionError {
    DnsExecutionError::new(
        message,
        Classification::new(
            "cli.dns_executor",
            Kind::Cli,
            Some("use one bounded UDP DNS query and retain at least one response"),
        ),
        Vec::new(),
    )
}
