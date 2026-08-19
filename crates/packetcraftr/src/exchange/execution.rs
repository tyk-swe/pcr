// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public exchange entry points and the prepare/arm/execute handoff.

use std::sync::Arc;

use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

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
        let mut collector = Collector::default();
        let summary =
            self.exchange_internal_with_events(template, options, None, &mut |event| {
                collector.observe(event);
                Ok(())
            })?;
        Ok(collector.finish(summary))
    }

    /// Runs one capture-ready exchange and publishes each event when final.
    pub fn exchange_with_events<F>(
        &self,
        template: &packetcraftr_core::template::Template,
        options: crate::exchange::Options,
        mut emit: F,
    ) -> Result<crate::exchange::Summary, Error>
    where
        F: FnMut(crate::exchange::Event) -> Result<(), crate::BoundaryError>,
    {
        self.exchange_internal_with_events(template, options, None, &mut emit)
    }

    pub(crate) fn exchange_internal(
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
        Ok(collector.finish(summary))
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
        let capture = self.io.arm_capture(first_route, prepared.capture_limits)?;
        Ok(Transaction::new(
            Arc::clone(&self.registry),
            capture,
            prepared,
        ))
    }
}
