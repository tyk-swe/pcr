// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::BoundaryError;

#[derive(Clone, Copy)]
pub(crate) struct ExecutorFault {
    code: &'static str,
    remediation: &'static str,
}

impl ExecutorFault {
    pub(crate) const fn new(code: &'static str, remediation: &'static str) -> Self {
        Self { code, remediation }
    }

    pub(crate) fn invalid(self, message: impl Into<String>) -> BoundaryError {
        BoundaryError::execution_validation(message, self.code, self.remediation)
    }

    pub(crate) fn internal(self, message: impl Into<String>) -> BoundaryError {
        BoundaryError::internal_execution(message, self.code, self.remediation)
    }
}

pub(crate) trait Step {
    type Evidence;
}

pub(crate) trait Executor<S: Step> {
    fn execute(&mut self, step: &S) -> Result<S::Evidence, BoundaryError>;
}

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

pub(crate) struct WorkflowOverrides {
    pub(crate) timeout: std::time::Duration,
    pub(crate) max_template_packets: usize,
    pub(crate) destination: std::net::IpAddr,
    /// The workflow's own evidence limit for this one exchange, or `None` to
    /// keep the executor's ceilings.
    pub(crate) max_responses: Option<usize>,
}

impl<P, K> ExchangeExecutor<'_, P, K>
where
    P: crate::Providers,
    K: crate::clock::Clock,
{
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
