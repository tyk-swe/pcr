// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public exchange entry points and the prepare/arm/execute handoff.

use std::sync::Arc;

use packetcraftr_netio::{capture::Provider as CaptureProvider, transmit::Sender as PacketIo};

use crate::Client;
use crate::Error;

use crate::exchange::{Prepared, Transaction, WorkflowResponseMatcher};
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
        self.exchange_internal(template, options, None)
    }

    pub(crate) fn exchange_internal(
        &self,
        template: &packetcraftr_core::template::Template,
        options: crate::exchange::Options,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<crate::exchange::Result, Error> {
        let prepared = self.prepare_exchange(template, options)?;
        let transaction = self.arm_capture(prepared)?;
        transaction.execute(&self.io, workflow_matcher)
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
