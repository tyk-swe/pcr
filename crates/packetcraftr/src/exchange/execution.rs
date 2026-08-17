// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public exchange entry points and the prepare/arm/execute handoff.

use std::sync::Arc;

use packetcraftr_core::template::Template as PacketTemplate;
use packetcraftr_netio::{
    capture::Provider as CaptureProvider, neighbor::Resolver as NeighborResolver,
    route::Provider as RouteProvider, transmit::Sender as PacketIo,
};

use crate::Client;
use crate::Error;
use crate::exchange::{Options as ExchangeOptions, Result as ExchangeResult};
use crate::exchange::{Prepared, Transaction, WorkflowResponseMatcher};
use crate::planning::ensure_preparation_deadline;

impl<R, N, I> Client<R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo + CaptureProvider,
{
    pub fn exchange(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
    ) -> Result<ExchangeResult, Error> {
        self.exchange_internal(template, options, None)
    }

    pub(crate) fn exchange_internal(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<ExchangeResult, Error> {
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
