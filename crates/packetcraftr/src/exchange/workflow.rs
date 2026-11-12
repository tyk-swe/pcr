// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exchanges run as the steps of a larger workflow.

use packetcraftr_core::error::BoundaryError;

use super::{Collection, Step, WorkflowEvidence, WorkflowResponseMatcher, WorkflowStopPredicate};
use crate::clock::{Clock, SystemClock};
use crate::engine::operation::Operation;
use crate::route::Interface;
use crate::{Client, PacketProviders, send};

/// Runs each step of a larger workflow as one exchange within the workflow's operation.
pub(crate) struct WorkflowExecutor<'a, P, K = SystemClock> {
    pub(crate) client: &'a Client<P, K>,
    pub(crate) operation: &'a Operation,
    pub(crate) send: send::Options,
    pub(crate) collection: Collection,
}

impl<'a, P, K> WorkflowExecutor<'a, P, K> {
    pub(crate) fn new(
        client: &'a Client<P, K>,
        operation: &'a Operation,
        send: send::Options,
        collection: Collection,
    ) -> Self {
        Self {
            client,
            operation,
            send,
            collection,
        }
    }
}

/// What one step changes about the workflow's shared exchange settings.
/// `destination` and `timeout` are required; the rest default to the
/// executor's own settings.
pub(crate) struct WorkflowStep {
    timeout: std::time::Duration,
    destination: std::net::IpAddr,
    interface: Option<packetcraftr_netio::interface::Id>,
    /// This exchange's own evidence limit, or `None` to keep the executor's.
    max_responses: Option<usize>,
    max_template_packets: usize,
}

impl WorkflowStep {
    pub(crate) const fn new(
        timeout: std::time::Duration,
        destination: std::net::IpAddr,
    ) -> Self {
        Self {
            timeout,
            destination,
            interface: None,
            max_responses: None,
            max_template_packets: 1,
        }
    }

    pub(crate) fn interface(mut self, interface: packetcraftr_netio::interface::Id) -> Self {
        self.interface = Some(interface);
        self
    }

    /// Caps this exchange's responses and its unmatched frames together.
    pub(crate) fn responses(mut self, max_responses: usize) -> Self {
        self.max_responses = Some(max_responses);
        self
    }

    pub(crate) fn template_packets(mut self, packets: usize) -> Self {
        self.max_template_packets = packets;
        self
    }
}

impl<P, K> WorkflowExecutor<'_, P, K>
where
    P: PacketProviders,
    K: Clock,
{
    pub(crate) fn exchange_for_workflow(
        &self,
        template: packetcraftr_core::template::Template,
        step: WorkflowStep,
        matches_request: &mut WorkflowResponseMatcher<'_>,
        stop_after_response: Option<&mut WorkflowStopPredicate<'_>>,
    ) -> Result<WorkflowEvidence, BoundaryError> {
        let mut send = self.send.clone();
        send.destination = Some(step.destination);
        if let Some(interface) = step.interface {
            send.plan.interface = Some(Interface::Id(interface));
        }
        let collection = match step.max_responses {
            Some(max_responses) => self.collection.clone().with_max_responses(max_responses),
            None => self.collection.clone(),
        };
        self.client
            .exchange_hooked(
                Step {
                    template,
                    send,
                    timeout: step.timeout,
                    max_template_packets: step.max_template_packets,
                    collection,
                },
                self.operation,
                Some(matches_request),
                stop_after_response,
            )
            .map_err(BoundaryError::from_error)
    }
}
