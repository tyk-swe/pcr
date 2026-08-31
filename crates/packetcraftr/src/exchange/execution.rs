// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public exchange entry points and the prepare/arm/execute handoff.

use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{BoundaryError, Classification, Kind};
use packetcraftr_netio::{
    capture::{Provider as CaptureProvider, Request as CaptureRequest},
    transmit::Sender as PacketIo,
};

use crate::Client;
use crate::Error;

use crate::exchange::{
    Collector, Prepared, Transaction, WorkflowResponseMatcher, WorkflowStopPredicate,
};
use crate::planning::ensure_preparation_deadline;

impl<R, N, I> Client<R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo + CaptureProvider,
{
    pub fn exchange(
        &self,
        template: &packetcraftr_core::template::Template,
        options: crate::exchange::Options,
    ) -> Result<crate::exchange::Report, Error> {
        self.exchange_hooked(template, options, None, None)
    }

    /// Runs one capture-ready exchange and publishes each event when final.
    ///
    /// Confirmed sends are published before later requests, capture evidence
    /// when its classification is final, and unanswered requests after capture
    /// shutdown. The callback runs on a one-event worker admitted by this
    /// client's [`Runtime`](packetcraftr_core::progress::Runtime); failure
    /// aborts later work, and the timeout bounds publisher waiting, not
    /// arbitrary callback execution. A callback may finish after this method
    /// returns and holds one of that runtime's worker permits until then.
    pub fn exchange_with_events<F>(
        &self,
        template: &packetcraftr_core::template::Template,
        options: crate::exchange::Options,
        emit: F,
    ) -> Result<crate::exchange::Summary, Error>
    where
        F: FnMut(crate::exchange::Event) -> Result<(), crate::BoundaryError> + Send + 'static,
    {
        let deadline = Deadline::new(options.timeout);
        let sink =
            packetcraftr_core::progress::Sink::new_in(&self.runtime, emit).map_err(|source| {
                Error::ExchangeOutput {
                    source: Box::new(source),
                }
            })?;
        self.exchange_streamed(template, options, None, None, &mut |event| {
            sink.emit(event, &deadline).map_err(exchange_sink_error)
        })
    }

    /// One collected exchange with the two optional workflow hooks: the
    /// matcher that gets a second chance at frames the registry matchers could
    /// not uniquely attribute, and the predicate that stops capture early.
    ///
    /// This is the only entry point workflow executors use; `exchange` is the
    /// same call with both hooks absent.
    pub(crate) fn exchange_hooked(
        &self,
        template: &packetcraftr_core::template::Template,
        options: crate::exchange::Options,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: Option<&mut WorkflowStopPredicate<'_>>,
    ) -> Result<crate::exchange::Report, Error> {
        let mut collector = Collector::default();
        let summary = self.exchange_streamed(
            template,
            options,
            workflow_matcher,
            stop_predicate,
            &mut |event| {
                collector.observe(event);
                Ok(())
            },
        )?;
        collector.finish(summary)
    }

    fn exchange_streamed<F>(
        &self,
        template: &packetcraftr_core::template::Template,
        options: crate::exchange::Options,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
        stop_predicate: Option<&mut WorkflowStopPredicate<'_>>,
        emit: &mut F,
    ) -> Result<crate::exchange::Summary, Error>
    where
        F: FnMut(crate::exchange::Event) -> Result<(), crate::BoundaryError>,
    {
        let prepared = self.prepare_exchange(template, options)?;
        let transaction = self.arm_capture(prepared)?;
        transaction.execute(&self.io, workflow_matcher, stop_predicate, emit)
    }

    fn arm_capture(
        &self,
        prepared: Prepared,
    ) -> Result<Transaction<<I as CaptureProvider>::Capture>, Error> {
        let first_route = &prepared
            .packets
            .first()
            .expect("non-empty prepared exchange")
            .route
            .plan;
        ensure_preparation_deadline(prepared.deadline)?;
        let capture = self.io.arm_capture(&CaptureRequest {
            interface: first_route.decision.interface.clone(),
            limits: prepared.options.capture,
            filter: None,
            promiscuous: false,
        })?;
        Ok(Transaction::new(
            Arc::clone(&self.registry),
            capture,
            prepared,
        ))
    }
}

fn exchange_sink_error(error: packetcraftr_core::progress::EmitError) -> BoundaryError {
    match error {
        packetcraftr_core::progress::EmitError::Output(source) => source,
        packetcraftr_core::progress::EmitError::Deadline(error) => BoundaryError::new(
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
        ),
    }
}
