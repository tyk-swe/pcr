// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Applies the client's traffic policy to a complete live fuzz campaign before
/// route, capture, neighbor, or transmission providers are invoked.
use super::{
    Duration, FuzzAuthorizer, FuzzCaseExecution, FuzzExecutionCase, FuzzExecutor, IpAddr,
    NeighborResolver, Packet, PacketTemplate, RouteProvider,
};
use crate::BoundaryError;
use crate::client_executor::{ClientExecutor, Fuzz};
use packetcraftr_net::{capture::CaptureProvider, transmit::PacketIo};

pub struct PolicyAuthorizer<'a> {
    policy: &'a packetcraftr_client::policy::Policy,
}

impl<'a> PolicyAuthorizer<'a> {
    pub fn new(policy: &'a packetcraftr_client::policy::Policy) -> Self {
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
    ) -> Result<(), BoundaryError> {
        self.policy.validate().map_err(BoundaryError::from_error)?;
        let packet_count = packets.len() as u64;
        self.policy
            .authorize_operation(packet_count, maximum_wire_bytes)
            .map_err(BoundaryError::from_error)?;
        if requires_malformed_live && !self.policy.allow_permissive_packets {
            return Err(BoundaryError::from_error(
                packetcraftr_client::policy::Error::PermissivePacket,
            ));
        }
        if let Some(destination) = destination {
            self.policy
                .authorize_destination(destination)
                .map_err(BoundaryError::from_error)?;
        }
        for packet in packets {
            self.policy
                .authorize_packet_destinations(packet)
                .map_err(BoundaryError::from_error)?;
        }
        Ok(())
    }
}

/// Executes one generated fuzz case through the client's capture-ready
/// exchange lifecycle.
impl<R, N, I> FuzzExecutor for ClientExecutor<'_, R, N, I, Fuzz>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(
        &mut self,
        case: &FuzzExecutionCase,
        timeout: Duration,
    ) -> Result<FuzzCaseExecution, BoundaryError> {
        let mut options = self.options.clone();
        options.timeout = timeout;
        options.max_template_packets = 1;
        let exchange = self
            .client
            .exchange(&PacketTemplate::new(case.packet.clone()), options)
            .map_err(BoundaryError::from_error)?;
        let packetcraftr_client::exchange::Result {
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

fn invalid_client_execution(message: impl Into<String>) -> BoundaryError {
    BoundaryError::internal_execution(
        message,
        "internal.fuzz_executor",
        "execute exactly one bounded fuzz case per capture-ready exchange",
    )
}
