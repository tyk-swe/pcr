// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{BoundaryError, Classification, Kind};

use super::{
    Aggregate, Error, Event, Observed, Report, Request, WorkflowResponseMatcher,
    WorkflowStopPredicate,
};
use crate::clock::Clock;
use crate::providers::Providers;
use crate::{Client, Sink};

impl<P: Providers, K: Clock> Client<P, K> {
    /// Runs one capture-ready exchange and publishes each event when final.
    /// Every packet is admitted before neighbor discovery or capture starts.
    /// A sink may finish after this method returns and holds a runtime worker permit until then.
    pub fn exchange<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let collection = self.deadline(request.timeout);
        // Post-window events get one more finite allowance; they cannot fall inside the window.
        let finalization_limit = request.timeout;
        let mut finalization: Option<Deadline> = None;
        let prepared = self.prepare_exchange(request)?;
        let mut publish =
            crate::execution::publisher(&self.runtime, sink, exchange_deadline_error, |source| {
                source
            })
            .map_err(|source| Error::Output {
                source: Box::new(source),
            })?;
        let transaction = self.arm_capture(prepared)?;
        transaction.execute(self.providers.transmit(), None, None, &mut |event| {
            let deadline = if collection.check().is_ok() {
                &collection
            } else {
                finalization.get_or_insert_with(|| self.deadline(finalization_limit))
            };
            publish(event, deadline)
        })
    }

    pub(crate) fn exchange_hooked(
        &self,
        request: Request,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: Option<&mut WorkflowStopPredicate<'_>>,
    ) -> Result<Aggregate, Error> {
        let mut observed = Observed::default();
        let transaction = self.arm_capture(self.prepare_exchange(request)?)?;
        let report = transaction.execute(
            self.providers.transmit(),
            workflow_matcher,
            stop_predicate,
            &mut |event| {
                observed.observe(event);
                Ok(())
            },
        )?;
        observed.finish(report)
    }
}

fn exchange_deadline_error(error: packetcraftr_core::budget::DeadlineExceeded) -> BoundaryError {
    BoundaryError::new(
        format!(
            "exchange progressive output exceeded the operation deadline of {:?}",
            error.limit
        ),
        Classification::new(
            "policy.exchange_duration_limit",
            Kind::Policy,
            Some("reduce exchange output backpressure or raise the finite timeout"),
        ),
        Vec::new(),
    )
}
