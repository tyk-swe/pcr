// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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

/// The exchange options one workflow call overrides, and nothing else: every
/// other bound comes from the executor's own [`crate::exchange::Options`].
pub(crate) struct WorkflowOverrides {
    pub(crate) timeout: std::time::Duration,
    pub(crate) max_template_packets: usize,
    pub(crate) destination: std::net::IpAddr,
    /// Caps both retained responses and retained unattributed frames for this
    /// one exchange, or `None` to keep the executor's own ceilings. A workflow
    /// that bounds how many responses it will accept never needs to retain
    /// more unattributed evidence than that.
    pub(crate) max_responses: Option<usize>,
}

impl<R, N, I> ExchangeExecutor<'_, R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: packetcraftr_netio::transmit::Sender + packetcraftr_netio::capture::Provider,
{
    /// Runs one capture-ready exchange for a workflow, with the executor's
    /// options as the base and `overrides` applied on top.
    pub(crate) fn exchange_for_workflow(
        &self,
        template: &packetcraftr_core::template::Template,
        overrides: WorkflowOverrides,
        matches_request: &mut crate::exchange::WorkflowResponseMatcher<'_>,
        stop_after_response: Option<&mut crate::exchange::WorkflowStopPredicate<'_>>,
    ) -> Result<crate::exchange::Report, crate::BoundaryError> {
        let mut options = self.options.clone();
        options.timeout = overrides.timeout;
        options.max_template_packets = overrides.max_template_packets;
        options.send.destination = Some(overrides.destination);
        if let Some(max_responses) = overrides.max_responses {
            options.max_responses = max_responses;
            options.max_unmatched_frames = options.max_unmatched_frames.min(max_responses);
        }
        self.client
            .exchange_hooked(
                template,
                options,
                Some(matches_request),
                stop_after_response,
            )
            .map_err(crate::BoundaryError::from_error)
    }
}
