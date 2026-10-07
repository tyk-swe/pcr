// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::error::{BoundaryError, Classification, Kind};
use packetcraftr_core::packet::Packet;

use super::{
    Error, Event, Observed, Report, Request, StopCondition, WorkflowResponseMatcher,
    WorkflowStopPredicate,
};
use crate::clock::Clock;
use crate::providers::PacketProviders;
use crate::{Client, Sink};

impl<P: PacketProviders, K: Clock> Client<P, K> {
    /// Runs one capture-ready exchange and publishes each event when final.
    /// The sink's runtime worker and every packet are admitted before neighbor discovery or
    /// capture starts.
    /// A sink may finish after this method returns and holds a runtime worker permit until then.
    pub fn exchange<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let stop = request.stop;
        let collection = self.deadline(request.timeout);
        // Post-window events get one more finite allowance; they cannot fall inside the window.
        let finalization_limit = request.timeout;
        let mut finalization: Option<Deadline> = None;
        let mut publish =
            crate::execution::publisher(&self.runtime, sink, exchange_deadline_error, |source| {
                source
            })
            .map_err(|source| Error::Output {
                source: Box::new(source),
            })?;
        let prepared = self.prepare_exchange(request)?;
        let mut answered = AnsweredRequests::new(prepared.packets.len());
        let mut stop_predicate =
            |request_index: usize, _: &Packet, _: &DecodedPacket| answered.record(request_index);
        let transaction = self.arm_capture(prepared)?;
        transaction
            .execute(
                self.providers.transmit(),
                None,
                (stop == StopCondition::AllAnswered)
                    .then_some(&mut stop_predicate as &mut WorkflowStopPredicate<'_>),
                &mut |event| {
                    let deadline = if collection.check().is_ok() {
                        &collection
                    } else {
                        finalization.get_or_insert_with(|| self.deadline(finalization_limit))
                    };
                    publish(event, deadline)
                },
            )
            .map(|(report, _)| report)
    }

    pub(crate) fn exchange_hooked(
        &self,
        request: Request,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: Option<&mut WorkflowStopPredicate<'_>>,
    ) -> Result<super::WorkflowEvidence, Error> {
        let mut observed = Observed::default();
        let transaction = self.arm_capture(self.prepare_exchange(request)?)?;
        let response_deadline = transaction.window.ends_at();
        let (report, unsolicited_ingress) = transaction.execute(
            self.providers.transmit(),
            workflow_matcher,
            stop_predicate,
            &mut |event| {
                observed.observe(event);
                Ok(())
            },
        )?;
        Ok(super::WorkflowEvidence {
            aggregate: observed.finish(report)?,
            unsolicited_ingress,
            response_deadline,
        })
    }
}

/// Distinct requests that have a retained response.
struct AnsweredRequests {
    answered: Vec<bool>,
    unanswered: usize,
}

impl AnsweredRequests {
    fn new(requests: usize) -> Self {
        Self {
            answered: vec![false; requests],
            unanswered: requests,
        }
    }

    /// Whether every request is answered once `request_index`'s response is counted.
    fn record(&mut self, request_index: usize) -> bool {
        if let Some(answered) = self.answered.get_mut(request_index)
            && !std::mem::replace(answered, true)
        {
            self.unanswered -= 1;
        }
        self.unanswered == 0
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
