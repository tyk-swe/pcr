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

/// One approved unit of live work a workflow hands to its executor, paired
/// with the evidence that work produces.
pub(crate) trait Step {
    type Evidence;
}

/// The executor boundary every live workflow shares: it carries out one
/// approved step and returns the evidence it produced. Implementations are
/// keyed by step type, so a scan executor and a DNS executor stay distinct.
pub(crate) trait Executor<S: Step> {
    fn execute(&mut self, step: &S) -> Result<S::Evidence, BoundaryError>;
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
    /// The workflow's own evidence limit for this one exchange, or `None` to
    /// keep the executor's ceilings. The workflow validates it against the
    /// executor's `max_responses` before calling, so it never raises a
    /// ceiling.
    ///
    /// It also sets this exchange's unattributed-frame budget, a derived
    /// running allowance rather than a configured limit: every frame the
    /// exchange retains, attributed or not, is evidence charged against the
    /// workflow's limit, so the budget is the smaller of the executor's
    /// `max_unmatched_frames` and this limit. No configured limit is lowered;
    /// the caller's settings stay as they were for later exchanges.
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
    ) -> Result<crate::exchange::Aggregate, packetcraftr_core::error::BoundaryError> {
        let mut send = self.send.clone();
        send.destination = Some(overrides.destination);
        let mut collection = self.collection.clone();
        if let Some(max_responses) = overrides.max_responses {
            collection.max_responses = max_responses;
            // The derived unattributed-frame budget documented on
            // `WorkflowOverrides::max_responses`, charged to this copy only.
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
            .map_err(packetcraftr_core::error::BoundaryError::from_error)
    }
}
