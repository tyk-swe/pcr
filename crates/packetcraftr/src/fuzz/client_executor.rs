// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Applies the client's traffic policy to a complete live fuzz campaign before
/// route, capture, neighbor, or transmission providers are invoked.
use std::net::IpAddr;
use std::time::Duration;

use crate::BoundaryError;
use crate::ExchangeExecutor;
use packetcraftr_core::Packet;
use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

use super::boundary::{Authorizer, Execution, ExecutionCase, Executor};

pub struct PolicyAuthorizer<'a> {
    policy: &'a crate::policy::Policy,
}

impl<'a> PolicyAuthorizer<'a> {
    pub fn new(policy: &'a crate::policy::Policy) -> Self {
        Self { policy }
    }
}

impl Authorizer for PolicyAuthorizer<'_> {
    fn authorize_operation(
        &mut self,
        packets: &[Packet],
        destination: Option<IpAddr>,
        maximum_wire_bytes: u64,
        requires_malformed_live: bool,
    ) -> Result<(), BoundaryError> {
        self.policy.validate().map_err(BoundaryError::from_error)?;
        let packet_count = u64::try_from(packets.len()).unwrap_or(u64::MAX);
        self.policy
            .authorize_operation(packet_count, maximum_wire_bytes)
            .map_err(BoundaryError::from_error)?;
        if requires_malformed_live && !self.policy.allow_permissive_packets {
            return Err(BoundaryError::from_error(
                crate::policy::Error::PermissivePacket,
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
impl<R, N, I> Executor for ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo + CaptureProvider,
{
    fn execute(
        &mut self,
        case: &ExecutionCase,
        timeout: Duration,
    ) -> Result<Execution, BoundaryError> {
        let mut options = self.options.clone();
        options.timeout = timeout;
        options.max_template_packets = 1;
        let exchange = self
            .client
            .exchange(
                &packetcraftr_core::template::Template::new(case.packet.clone()),
                options,
            )
            .map_err(BoundaryError::from_error)?;
        let crate::exchange::Result {
            mut sent,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = exchange;
        if sent.len() != 1 {
            return Err(invalid_client_execution(format!(
                "expected one sent receipt, received {}",
                sent.len()
            )));
        }
        let sent =
            crate::exchange::into_sent_packet(sent.pop().expect("validated one sent fuzz packet"));
        Ok(Execution {
            permit: case.permit,
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
