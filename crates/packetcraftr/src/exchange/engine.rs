// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{BoundaryError, Classification, Kind};
use packetcraftr_netio::capture::{Provider as CaptureProvider, Request as CaptureRequest};

use super::{
    Aggregate, Collection, Error, Event, Observed, Report, Request, Transaction, Window,
    WorkflowResponseMatcher, WorkflowStopPredicate,
};
use crate::clock::Clock;
use crate::planning::ensure_preparation_deadline;
use crate::preparation::{Admitted, PreparedPacket};
use crate::providers::Providers;
use crate::route::CachedProvider;
use crate::{Client, Sink};

type Session<P> = <<P as Providers>::Capture as CaptureProvider>::Capture;

impl<P: Providers, K: Clock> Client<P, K> {
    /// Runs one capture-ready exchange and publishes each event when final.
    ///
    /// The count-only budget and every packet's destinations are authorized
    /// before any provider is consulted, and every packet is admitted before
    /// neighbor discovery or capture starts. Confirmed sends are published
    /// before later requests, capture evidence when its classification is
    /// final, and unanswered requests after capture shutdown. `sink` runs on
    /// a one-event worker admitted by the client's
    /// [`Runtime`](crate::runtime::Runtime); a failure aborts later work. The
    /// timeout bounds waiting for the sink, not the sink itself: once for the
    /// collection window and once more for the events published after it
    /// closes. A sink may finish after this method returns and holds one of
    /// the runtime's worker permits until then.
    ///
    /// # Errors
    ///
    /// Returns the invalid request, the preparation or provider failure, a
    /// route the packets do not share, or the sink's failure, together with
    /// any capture shutdown failure.
    pub fn exchange<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let collection = self.deadline(request.timeout);
        // Unanswered requests and the final best-effort drain are published
        // only after the collection window closes, so they get one further
        // finite allowance instead of the window they cannot fall inside.
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

    /// Exchange with optional fallback matching and early capture
    /// termination, collected inline without a worker. Workflow executors
    /// use this entry point.
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

    fn arm_capture(&self, prepared: Prepared) -> Result<Transaction<Session<P>>, Error> {
        let Some(first_packet) = prepared.packets.first() else {
            return Err(crate::Error::Template {
                message: "template expanded to no packets".to_owned(),
                source: None,
            }
            .into());
        };
        let first_route = &first_packet.route().plan;
        ensure_preparation_deadline(prepared.window.deadline())?;
        self.check_cancelled()?;
        let capture = self.providers.capture().arm_capture(
            &CaptureRequest {
                interface: first_route.decision.interface.clone(),
                limits: prepared.collection.capture,
                filter: None,
                promiscuous: false,
                native: Default::default(),
            },
            prepared.window.deadline(),
        )?;
        Ok(Transaction::new(
            Arc::clone(&self.registry),
            capture,
            prepared,
        ))
    }

    fn prepare_exchange(&self, request: Request) -> Result<Prepared, Error> {
        self.check_cancelled()?;
        request.validate()?;
        let Request {
            template,
            send,
            timeout,
            max_template_packets,
            collection,
        } = request;
        let window =
            Window::open(&self.clock, timeout, self.cancellation.clone()).ok_or_else(|| {
                Error::InvalidRequest {
                    field: "timeout",
                    message: "cannot be represented by the platform monotonic clock".to_owned(),
                }
            })?;
        let expansion_len = template
            .expansion_len()
            .map_err(|source| crate::Error::Template {
                message: source.to_string(),
                source: Some(source),
            })?;
        let packet_count = u64::try_from(expansion_len).unwrap_or(u64::MAX);
        let mut admission = self.admitting(&send, packet_count, window.deadline())?;
        if expansion_len == 0 {
            return Err(crate::Error::Template {
                message: "template expanded to no packets".to_owned(),
                source: None,
            }
            .into());
        }
        let mut expanded_packets =
            template
                .expand(max_template_packets)
                .map_err(|source| crate::Error::Template {
                    message: source.to_string(),
                    source: Some(source),
                })?;
        let routes = CachedProvider::new(self.providers.route());
        let mut admitted: Vec<Admitted> = Vec::with_capacity(expanded_packets.len());
        loop {
            // Expansion allocates, so the operation's stop conditions are
            // checked before each packet is pulled.
            admission.check()?;
            let Some(expanded_packet) = expanded_packets.next() else {
                break;
            };
            let packet = expanded_packet.map_err(|source| crate::Error::Template {
                message: source.to_string(),
                source: Some(source),
            })?;
            let admitted_packet = admission.admit(packet, &routes)?;
            if let Some(first_packet) = admitted.first()
                && !first_packet.shares_route_with(&admitted_packet)
            {
                return Err(Error::HeterogeneousRoute);
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
        drop(discovery);

        Ok(Prepared {
            cancellation: self.cancellation.clone(),
            window,
            collection,
            packets,
            packet_count,
            total_bytes,
        })
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

/// Every packet of one exchange, admitted and materialized, with the window
/// and collection bounds its capture runs under.
pub(crate) struct Prepared {
    pub(crate) cancellation: Option<packetcraftr_core::budget::Cancellation>,
    pub(crate) window: Window,
    pub(crate) collection: Collection,
    pub(crate) packets: Vec<PreparedPacket>,
    pub(crate) packet_count: u64,
    pub(crate) total_bytes: u64,
}
