// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::Packet;
use packetcraftr_core::error::BoundaryError;

/// Stable failure coordinates for one workflow executor: the classification
/// code and remediation every contract breach in that executor reports.
#[derive(Clone, Copy)]
pub(crate) struct ExecutorFault {
    code: &'static str,
    remediation: &'static str,
}

impl ExecutorFault {
    pub(crate) const fn new(code: &'static str, remediation: &'static str) -> Self {
        Self { code, remediation }
    }

    /// Reports invalid executor input as a caller validation failure.
    pub(crate) fn invalid(self, message: impl Into<String>) -> BoundaryError {
        BoundaryError::execution_validation(message, self.code, self.remediation)
    }

    /// Reports a broken executor contract as an internal invariant failure.
    pub(crate) fn internal(self, message: impl Into<String>) -> BoundaryError {
        BoundaryError::internal_execution(message, self.code, self.remediation)
    }
}

/// Shared client and exchange options for live workflow executors.
pub struct ExchangeExecutor<'a, R, N, I> {
    pub(crate) client: &'a crate::Client<R, N, I>,
    pub(crate) options: crate::exchange::Options,
}

impl<'a, R, N, I> ExchangeExecutor<'a, R, N, I> {
    pub fn new(client: &'a crate::Client<R, N, I>, options: crate::exchange::Options) -> Self {
        Self { client, options }
    }
}

impl<R, N, I> ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: packetcraftr_netio::transmit::Sender + packetcraftr_netio::capture::Provider,
{
    pub(crate) fn exchange_for_workflow(
        &self,
        template: &packetcraftr_core::template::Template,
        timeout: std::time::Duration,
        max_template_packets: usize,
        destination: std::net::IpAddr,
        mut matches_request: impl FnMut(
            usize,
            &Packet,
            &packetcraftr_core::decode::DecodedPacket,
        ) -> bool,
    ) -> Result<crate::exchange::Result, crate::BoundaryError> {
        let mut options = self.options.clone();
        options.timeout = timeout;
        options.max_template_packets = max_template_packets;
        options.send.destination = Some(destination);
        self.client
            .exchange_internal(template, options, Some(&mut matches_request))
            .map_err(crate::BoundaryError::from_error)
    }

    pub(crate) fn exchange_for_workflow_until(
        &self,
        template: &packetcraftr_core::template::Template,
        timeout: std::time::Duration,
        max_template_packets: usize,
        destination: std::net::IpAddr,
        mut matches_request: impl FnMut(
            usize,
            &Packet,
            &packetcraftr_core::decode::DecodedPacket,
        ) -> bool,
        mut stop_after_response: impl FnMut(
            usize,
            &Packet,
            &packetcraftr_core::decode::DecodedPacket,
        ) -> bool,
    ) -> Result<crate::exchange::Result, crate::BoundaryError> {
        let mut options = self.options.clone();
        options.timeout = timeout;
        options.max_template_packets = max_template_packets;
        options.send.destination = Some(destination);
        self.client
            .exchange_internal_until(
                template,
                options,
                Some(&mut matches_request),
                &mut stop_after_response,
            )
            .map_err(crate::BoundaryError::from_error)
    }
}
