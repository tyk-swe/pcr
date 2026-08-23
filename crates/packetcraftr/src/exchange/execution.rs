// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public exchange entry points and the prepare/arm/execute handoff.

use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{BoundaryError, Classification};
use packetcraftr_netio::{
    capture::{Provider as CaptureProvider, Request as CaptureRequest},
    transmit::Sender as PacketIo,
};

use crate::Client;
use crate::Error;

use crate::exchange::{Collector, Prepared, Transaction, WorkflowResponseMatcher};
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
    ) -> Result<crate::exchange::Result, Error> {
        self.exchange_collected(template, options, None)
    }

    /// Runs one capture-ready exchange and publishes each event when final.
    ///
    /// Confirmed sends are published before later requests, capture evidence
    /// when its classification is final, and unanswered requests after capture
    /// shutdown. The callback runs on a one-event worker; failure aborts later
    /// work and backpressure cannot exceed the exchange timeout. A callback
    /// that outlives that timeout may finish after this method returns and must
    /// own its state.
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
            packetcraftr_core::progress::Sink::new(emit).map_err(|source| Error::Output {
                source: Box::new(source),
            })?;
        self.exchange_internal_with_events(template, options, None, &mut |event| {
            sink.emit(event, &deadline).map_err(exchange_sink_error)
        })
    }

    pub(crate) fn exchange_internal(
        &self,
        template: &packetcraftr_core::template::Template,
        options: crate::exchange::Options,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<crate::exchange::Result, Error> {
        self.exchange_collected(template, options, workflow_matcher)
    }

    fn exchange_collected(
        &self,
        template: &packetcraftr_core::template::Template,
        options: crate::exchange::Options,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<crate::exchange::Result, Error> {
        let mut collector = Collector::default();
        let summary = self.exchange_internal_with_events(
            template,
            options,
            workflow_matcher,
            &mut |event| {
                collector.observe(event);
                Ok(())
            },
        )?;
        collector.finish(summary)
    }

    fn exchange_internal_with_events<F>(
        &self,
        template: &packetcraftr_core::template::Template,
        options: crate::exchange::Options,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
        emit: &mut F,
    ) -> Result<crate::exchange::Summary, Error>
    where
        F: FnMut(crate::exchange::Event) -> Result<(), crate::BoundaryError>,
    {
        let prepared = self.prepare_exchange(template, options)?;
        let transaction = self.arm_capture(prepared)?;
        transaction.execute(&self.io, workflow_matcher, emit)
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
            limits: prepared.capture_limits,
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
                "policy.duration_limit",
                Some("reduce output backpressure or deliberately raise the finite duration limit"),
            ),
            Vec::new(),
        ),
    }
}
