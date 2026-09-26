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

/// One unit of live work a workflow hands to its executor, paired with the
/// evidence receipt that work produces.
pub(crate) trait Request {
    type Execution;
}

/// The executor boundary every live workflow shares: it carries out one
/// approved request and returns the evidence it produced. Implementations are
/// keyed by request type, so a scan executor and a DNS executor stay distinct.
pub(crate) trait Executor<Req: Request> {
    fn execute(&mut self, request: &Req) -> Result<Req::Execution, BoundaryError>;
}

/// Runs each approved workflow step as one capture-ready exchange on a
/// client, preparing every packet with `send` and collecting under
/// `collection`.
pub(crate) struct ExchangeExecutor<'a, P, K = crate::clock::SystemClock> {
    pub(crate) client: &'a crate::Client<P, K>,
    pub(crate) send: crate::send::Options,
    pub(crate) collection: crate::exchange::Collection,
}

impl<'a, P, K> ExchangeExecutor<'a, P, K> {
    pub(crate) fn new(
        client: &'a crate::Client<P, K>,
        send: crate::send::Options,
        collection: crate::exchange::Collection,
    ) -> Self {
        Self {
            client,
            send,
            collection,
        }
    }
}

/// The exchange settings one workflow call overrides, and nothing else:
/// every other bound comes from the executor's own send options and
/// collection.
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

impl<P, K> ExchangeExecutor<'_, P, K>
where
    P: crate::Providers,
    K: crate::clock::Clock,
{
    /// Runs one capture-ready exchange for a workflow, with the executor's
    /// settings as the base and `overrides` applied on top.
    pub(crate) fn exchange_for_workflow(
        &self,
        template: packetcraftr_core::template::Template,
        overrides: WorkflowOverrides,
        matches_request: &mut crate::exchange::WorkflowResponseMatcher<'_>,
        stop_after_response: Option<&mut crate::exchange::WorkflowStopPredicate<'_>>,
    ) -> Result<crate::exchange::Aggregate, crate::BoundaryError> {
        let mut send = self.send.clone();
        send.destination = Some(overrides.destination);
        let mut collection = self.collection.clone();
        if let Some(max_responses) = overrides.max_responses {
            collection.max_responses = max_responses;
            collection.max_unmatched_frames = collection.max_unmatched_frames.min(max_responses);
        }
        self.client
            .exchange_hooked(
                crate::exchange::Request {
                    template,
                    send,
                    timeout: overrides.timeout,
                    max_template_packets: overrides.max_template_packets,
                    collection,
                },
                Some(matches_request),
                stop_after_response,
            )
            .map_err(crate::BoundaryError::from_error)
    }
}
