// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exchanges run as the steps of a larger workflow.

use packetcraftr_core::error::BoundaryError;

use super::{
    Collection, Request, StopCondition, WorkflowEvidence, WorkflowResponseMatcher,
    WorkflowStopPredicate,
};
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
pub(crate) struct WorkflowOverrides {
    pub(crate) timeout: std::time::Duration,
    pub(crate) max_template_packets: usize,
    pub(crate) destination: std::net::IpAddr,
    pub(crate) interface: Option<packetcraftr_netio::interface::Id>,
    /// The workflow's own evidence limit for this one exchange, or `None` to
    /// keep the executor's ceilings.
    pub(crate) max_responses: Option<usize>,
}

impl<P, K> WorkflowExecutor<'_, P, K>
where
    P: PacketProviders,
    K: Clock,
{
    pub(crate) fn exchange_for_workflow(
        &self,
        template: packetcraftr_core::template::Template,
        overrides: WorkflowOverrides,
        matches_request: &mut WorkflowResponseMatcher<'_>,
        stop_after_response: Option<&mut WorkflowStopPredicate<'_>>,
    ) -> Result<WorkflowEvidence, BoundaryError> {
        let mut send = self.send.clone();
        send.destination = Some(overrides.destination);
        if let Some(interface) = overrides.interface {
            send.plan.interface = Some(Interface::Id(interface));
        }
        let mut collection = self.collection.clone();
        if let Some(max_responses) = overrides.max_responses {
            collection.max_responses = max_responses;
            collection.max_unmatched_frames = collection.max_unmatched_frames.min(max_responses);
        }
        self.client
            .exchange_hooked(
                Request {
                    template,
                    send,
                    timeout: overrides.timeout,
                    max_template_packets: overrides.max_template_packets,
                    collection,
                    stop: StopCondition::Window,
                },
                self.operation,
                Some(matches_request),
                stop_after_response,
            )
            .map_err(BoundaryError::from_error)
    }
}
