// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public exchange entry points and the prepare/arm/execute handoff.

use std::sync::Arc;

use packetcraftr_network::{
    capture::Provider as CaptureProvider, neighbor::Resolver as NeighborResolver,
    route::Provider as RouteProvider, transmit::Sender as PacketIo,
};
use packetcraftr_packet::{Packet, template::Template as PacketTemplate};

use crate::Client;
use crate::exchange::{
    ExchangeOptions, ExchangeResult, ExchangeTransaction, PreparedExchange, WorkflowResponseMatcher,
};
use crate::planning::ensure_preparation_deadline;
use crate::send::ClientError;

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
    ) -> Result<ExchangeResult, ClientError> {
        self.exchange_internal(template, options, None)
    }

    /// Exchange seam used by the bounded workflows to correlate responses to
    /// the request that produced them. Not part of the documented API.
    #[doc(hidden)]
    pub fn exchange_for_workflow(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
        mut matches_request: impl FnMut(usize, &Packet, &packetcraftr_packet::decode::Result) -> bool,
    ) -> Result<ExchangeResult, ClientError> {
        self.exchange_internal(template, options, Some(&mut matches_request))
    }

    fn exchange_internal(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<ExchangeResult, ClientError> {
        let prepared = self.prepare_exchange(template, options)?;
        let transaction = self.arm_capture(prepared)?;
        transaction.execute(&self.io, workflow_matcher)
    }

    fn arm_capture(
        &self,
        prepared: PreparedExchange,
    ) -> Result<ExchangeTransaction<<I as CaptureProvider>::Capture>, ClientError> {
        let first_route = &prepared
            .packets
            .first()
            .expect("non-empty prepared exchange")
            .route
            .plan;
        ensure_preparation_deadline(prepared.deadline)?;
        let capture = self.io.arm_capture(first_route, prepared.capture_limits)?;
        Ok(ExchangeTransaction::new(
            Arc::clone(&self.registry),
            capture,
            prepared,
        ))
    }
}
