/// Applies the client's traffic policy to a complete live fuzz campaign before
/// route, capture, neighbor, or transmission providers are invoked.
pub struct PolicyAuthorizer<'a> {
    policy: &'a crate::client::policy::Policy,
}

impl<'a> PolicyAuthorizer<'a> {
    pub fn new(policy: &'a crate::client::policy::Policy) -> Self {
        Self { policy }
    }
}

impl FuzzAuthorizer for PolicyAuthorizer<'_> {
    fn authorize_operation(
        &mut self,
        packets: &[Packet],
        destination: Option<IpAddr>,
        maximum_wire_bytes: u64,
        requires_malformed_live: bool,
    ) -> Result<(), FuzzAuthorizationError> {
        use crate::client::policy::Error as PolicyError;

        self.policy
            .validate()
            .map_err(|error| FuzzAuthorizationError::classified(&error))?;
        let packet_count = packets.len() as u64;
        if packet_count > self.policy.max_packets_per_operation {
            return Err(FuzzAuthorizationError::classified(
                &PolicyError::PacketLimit {
                    actual: packet_count,
                    limit: self.policy.max_packets_per_operation,
                },
            ));
        }
        if maximum_wire_bytes > self.policy.max_bytes_per_operation {
            return Err(FuzzAuthorizationError::classified(
                &PolicyError::ByteLimit {
                    actual: maximum_wire_bytes,
                    limit: self.policy.max_bytes_per_operation,
                },
            ));
        }
        if requires_malformed_live && !self.policy.allow_permissive_packets {
            return Err(FuzzAuthorizationError::classified(
                &PolicyError::PermissivePacket,
            ));
        }
        if let Some(destination) = destination {
            self.policy
                .authorize_destination(destination)
                .map_err(|error| FuzzAuthorizationError::classified(&error))?;
        }
        for packet in packets {
            self.policy
                .authorize_packet_destinations(packet)
                .map_err(|error| FuzzAuthorizationError::classified(&error))?;
        }
        Ok(())
    }
}

/// Executes one generated fuzz case through the client's capture-ready
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

impl<R, N, I> FuzzExecutor for ClientExecutor<'_, R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: ExchangeIo,
{
    fn execute(
        &mut self,
        case: &FuzzExecutionCase,
        timeout: Duration,
    ) -> Result<FuzzCaseExecution, FuzzExecutionError> {
        let mut options = self.options.clone();
        options.timeout = timeout;
        options.max_template_packets = 1;
        let exchange = self
            .client
            .exchange(&PacketTemplate::new(case.packet.clone()), options)
            .map_err(|error| FuzzExecutionError::classified(&error))?;
        let crate::client::exchange::Result {
            mut sent,
            mut sent_evidence,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = exchange;
        if sent.len() != 1 || sent_evidence.len() != 1 {
            return Err(invalid_client_execution(format!(
                "expected one built and sent frame, received {} built and {} sent",
                sent.len(),
                sent_evidence.len()
            )));
        }
        let built = sent.pop().expect("validated one built fuzz packet");
        let sent = sent_evidence.pop().expect("validated one sent fuzz frame");
        Ok(FuzzCaseExecution {
            built,
            sent,
            responses: responses
                .into_iter()
                .map(|response| response.response.frame)
                .collect(),
            unmatched: unsolicited
                .into_iter()
                .map(|response| response.frame)
                .collect(),
            undecoded,
            diagnostics,
            stats,
        })
    }
}

fn invalid_client_execution(message: impl Into<String>) -> FuzzExecutionError {
    FuzzExecutionError::internal_execution(
        message,
        "internal.fuzz_executor",
        "execute exactly one bounded fuzz case per capture-ready exchange",
    )
}
use super::{
    Duration, ExchangeIo, FuzzAuthorizationError, FuzzAuthorizer, FuzzCaseExecution,
    FuzzExecutionCase, FuzzExecutionError, FuzzExecutor, IpAddr, NeighborResolver, Packet,
    PacketTemplate, RouteProvider,
};
