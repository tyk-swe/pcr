// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{BoundaryError, Classification, Kind};
use packetcraftr_core::template;
use packetcraftr_netio::{
    capture::{Provider as CaptureProvider, Request as CaptureRequest},
    transmit::Sender as PacketIo,
};

use packetcraftr_netio::{neighbor, route, transmit};

use super::model::Options;
use super::route_cache::CachedProvider;
use crate::Client;
use crate::Error;

use crate::exchange::{Collector, Transaction, WorkflowResponseMatcher, WorkflowStopPredicate};
use crate::planning::ensure_preparation_deadline;
use crate::preparation::{Admitted, PreparedPacket};

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
    /// client's [`Runtime`](crate::progress::Runtime); failure
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
        let deadline = Deadline::new(options.timeout).with_cancellation(self.cancellation.clone());
        let sink = crate::progress::Sink::new_in(&self.runtime, emit).map_err(|source| {
            Error::ExchangeOutput {
                source: Box::new(source),
            }
        })?;
        self.exchange_streamed(template, options, None, None, &mut |event| {
            sink.emit(event, &deadline).map_err(exchange_sink_error)
        })
    }

    /// Exchange with optional fallback matching and early capture termination.
    /// Workflow executors use this entry point; `exchange` supplies neither
    /// hook.
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
    ) -> Result<
        Transaction<packetcraftr_netio::capture::Cancellable<<I as CaptureProvider>::Capture>>,
        Error,
    > {
        let Some(first_packet) = prepared.packets.first() else {
            return Err(Error::Template {
                message: "template expanded to no packets".to_owned(),
                source: None,
            });
        };
        let first_route = &first_packet.route().plan;
        ensure_preparation_deadline(prepared.deadline)?;
        self.check_cancelled()?;
        let capture = self.io.arm_capture(&CaptureRequest {
            interface: first_route.decision.interface.clone(),
            limits: prepared.options.capture,
            filter: None,
            promiscuous: false,
            native: Default::default(),
        })?;
        Ok(Transaction::new(
            Arc::clone(&self.registry),
            packetcraftr_netio::capture::Cancellable::new(capture, self.cancellation.clone()),
            prepared,
        ))
    }
}

fn exchange_sink_error(error: crate::progress::EmitError) -> BoundaryError {
    match error {
        crate::progress::EmitError::Output(source) => source,
        crate::progress::EmitError::Deadline(error) => BoundaryError::new(
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

pub(crate) struct Prepared {
    pub(crate) cancellation: Option<packetcraftr_core::budget::Cancellation>,
    pub(crate) started: Instant,
    pub(crate) deadline: Instant,
    pub(crate) options: Options,
    pub(crate) packets: Vec<PreparedPacket>,
    pub(crate) packet_count: u64,
    pub(crate) total_bytes: u64,
}

impl<R, N, I> Client<R, N, I>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    pub(super) fn prepare_exchange(
        &self,
        template: &template::Template,
        options: Options,
    ) -> Result<Prepared, Error> {
        self.check_cancelled()?;
        let started = Instant::now();
        options.validate()?;
        let deadline = started
            .checked_add(options.timeout)
            .expect("validated bounded exchange timeout must fit Instant");
        let expansion_len = template.expansion_len().map_err(|source| Error::Template {
            message: source.to_string(),
            source: Some(source),
        })?;
        let packet_count = u64::try_from(expansion_len).unwrap_or(u64::MAX);
        let mut admission = self.admission(&options.send, packet_count, deadline)?;
        if expansion_len == 0 {
            return Err(Error::Template {
                message: "template expanded to no packets".to_owned(),
                source: None,
            });
        }
        let mut expanded_packets =
            template
                .expand(options.max_template_packets)
                .map_err(|source| Error::Template {
                    message: source.to_string(),
                    source: Some(source),
                })?;
        let routes = CachedProvider::new(&self.routes);
        let mut admitted: Vec<Admitted> = Vec::with_capacity(expanded_packets.len());
        loop {
            // Expansion allocates, so the operation's stop conditions are
            // checked before each packet is pulled.
            admission.check()?;
            let Some(expanded_packet) = expanded_packets.next() else {
                break;
            };
            let packet = expanded_packet.map_err(|source| Error::Template {
                message: source.to_string(),
                source: Some(source),
            })?;
            let admitted_packet = admission.admit(packet, &routes)?;
            if let Some(first_packet) = admitted.first()
                && !first_packet.shares_route_with(&admitted_packet)
            {
                return Err(Error::HeterogeneousExchangeRoute);
            }
            admitted.push(admitted_packet);
        }
        let total_bytes = admission.wire_bytes();
        // Neighbor discovery is delayed until every packet has passed packet,
        // route, permissive-build, and aggregate byte-policy checks.
        let discovery = admission.discover();
        let packets = admitted
            .into_iter()
            .map(|packet| discovery.materialize(packet))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Prepared {
            cancellation: self.cancellation.clone(),
            started,
            deadline,
            options,
            packets,
            packet_count,
            total_bytes,
        })
    }
}
