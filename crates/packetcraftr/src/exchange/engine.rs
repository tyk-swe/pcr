// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::error::{BoundaryError, Classification, Kind};
use packetcraftr_core::packet::Packet;

use super::{
    Error, Event, Observed, Report, Request, Step, StopCondition, WorkflowResponseMatcher,
    WorkflowStopPredicate,
};
use crate::clock::Clock;
use crate::providers::PacketProviders;
use crate::{Client, Sink};

pub(crate) enum ExchangeInput {
    Step(Step),
    Packets {
        packets: Vec<Packet>,
        send: crate::send::Options,
        timeout: std::time::Duration,
        collection: super::Collection,
    },
}

pub(crate) struct WorkflowExchange<'o, 'm, 'md, 's, 'sd, 'p> {
    pub(crate) input: ExchangeInput,
    pub(crate) operation: &'o crate::engine::operation::Operation,
    pub(crate) matcher: Option<&'m mut WorkflowResponseMatcher<'md>>,
    pub(crate) stop: Option<&'s mut WorkflowStopPredicate<'sd>>,
    pub(crate) pinned: Option<&'p mut Option<crate::route::Plan>>,
    pub(crate) authoritative_matcher: bool,
}

impl<'o> WorkflowExchange<'o, '_, '_, '_, '_, '_> {
    pub(crate) fn step(step: Step, operation: &'o crate::engine::operation::Operation) -> Self {
        Self {
            input: ExchangeInput::Step(step),
            operation,
            matcher: None,
            stop: None,
            pinned: None,
            authoritative_matcher: false,
        }
    }

    pub(crate) fn packets(
        packets: Vec<Packet>,
        send: crate::send::Options,
        timeout: std::time::Duration,
        collection: super::Collection,
        operation: &'o crate::engine::operation::Operation,
    ) -> Self {
        Self {
            input: ExchangeInput::Packets {
                packets,
                send,
                timeout,
                collection,
            },
            operation,
            matcher: None,
            stop: None,
            pinned: None,
            authoritative_matcher: false,
        }
    }
}

impl<'o, 'm, 'md, 's, 'sd, 'p> WorkflowExchange<'o, 'm, 'md, 's, 'sd, 'p> {
    pub(crate) fn with_matcher<'m2, 'md2>(
        self,
        matcher: &'m2 mut WorkflowResponseMatcher<'md2>,
    ) -> WorkflowExchange<'o, 'm2, 'md2, 's, 'sd, 'p> {
        WorkflowExchange {
            input: self.input,
            operation: self.operation,
            matcher: Some(matcher),
            stop: self.stop,
            pinned: self.pinned,
            authoritative_matcher: self.authoritative_matcher,
        }
    }

    pub(crate) fn with_authoritative_matcher<'m2, 'md2>(
        self,
        matcher: &'m2 mut WorkflowResponseMatcher<'md2>,
    ) -> WorkflowExchange<'o, 'm2, 'md2, 's, 'sd, 'p> {
        WorkflowExchange {
            input: self.input,
            operation: self.operation,
            matcher: Some(matcher),
            stop: self.stop,
            pinned: self.pinned,
            authoritative_matcher: true,
        }
    }

    pub(crate) fn with_stop<'s2, 'sd2>(
        self,
        stop: Option<&'s2 mut WorkflowStopPredicate<'sd2>>,
    ) -> WorkflowExchange<'o, 'm, 'md, 's2, 'sd2, 'p> {
        WorkflowExchange {
            input: self.input,
            operation: self.operation,
            matcher: self.matcher,
            stop,
            pinned: self.pinned,
            authoritative_matcher: self.authoritative_matcher,
        }
    }

    pub(crate) fn with_pinned<'p2>(
        self,
        pinned: &'p2 mut Option<crate::route::Plan>,
    ) -> WorkflowExchange<'o, 'm, 'md, 's, 'sd, 'p2> {
        WorkflowExchange {
            input: self.input,
            operation: self.operation,
            matcher: self.matcher,
            stop: self.stop,
            pinned: Some(pinned),
            authoritative_matcher: self.authoritative_matcher,
        }
    }
}

impl<P: PacketProviders, K: Clock> Client<P, K> {
    /// Runs one capture-ready exchange and publishes each event when final.
    /// The sink's runtime worker and every packet are admitted before neighbor discovery or
    /// capture starts.
    /// A sink may finish after this method returns and holds a runtime worker permit until then.
    pub fn exchange<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let operation = crate::engine::operation::Operation::new(self, std::time::Duration::MAX);
        let stop = request.stop;
        let collection = self.deadline(request.timeout);
        // Post-window events get one more finite allowance; they cannot fall inside the window.
        let finalization_limit = request.timeout;
        let mut finalization: Option<Deadline> = None;
        let mut publish =
            crate::engine::execution::publisher(sink, exchange_deadline_error, |source| source)
                .map_err(|source| Error::Output {
                    source: Box::new(source),
                })?;
        let prepared = self.prepare_exchange(request, &operation)?;
        let mut answered = AnsweredRequests::new(prepared.packets.len());
        let mut stop_predicate =
            |request_index: usize, _: &Packet, _: &DecodedPacket| answered.record(request_index);
        let transaction = self.arm_capture(prepared, &operation)?;
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
            .map(|(report, _, _)| report)
    }

    pub(crate) fn exchange_workflow(
        &self,
        exchange: WorkflowExchange<'_, '_, '_, '_, '_, '_>,
    ) -> Result<super::WorkflowEvidence, Error> {
        let WorkflowExchange {
            input,
            operation,
            matcher,
            stop,
            pinned,
            authoritative_matcher,
        } = exchange;
        let prepared = match input {
            ExchangeInput::Step(step) => self.prepare_step(step, operation)?,
            ExchangeInput::Packets {
                packets,
                send,
                timeout,
                collection,
            } => self.prepare_packet_exchange(
                packets.len(),
                || Ok(packets.into_iter().map(Ok)),
                &send,
                timeout,
                collection,
                operation,
                pinned,
            )?,
        };
        let mut transaction = self.arm_capture(prepared, operation)?;
        if authoritative_matcher {
            transaction.captured.authoritative_matcher = true;
        }
        let response_deadline = transaction.window.ends_at();
        let mut observed = Observed::default();
        let (report, unsolicited_ingress, observation_quality) =
            transaction.execute(self.providers.transmit(), matcher, stop, &mut |event| {
                observed.observe(event);
                Ok(())
            })?;
        Ok(super::WorkflowEvidence {
            observation_quality,
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
            crate::code::PolicyExchangeDurationLimit,
            Kind::Policy,
            Some("reduce exchange output backpressure or raise the finite timeout"),
        ),
        Vec::new(),
    )
}
