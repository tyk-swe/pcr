// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! How the client carries out scan batches: one exchange per probe, or a
//! rolling window of probes over one capture group.

mod pipeline;
mod registry;

pub(super) use pipeline::limit;
pub use pipeline::{PendingEvidence, PipelineFailure};

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::execution::{ExchangeExecutor, Executor, ExecutorFault, WorkflowOverrides};
use crate::probe::{Batch, Execution};
use crate::providers::Providers;
use crate::{BoundaryError, Client, SentPacket, Stats};

use super::Probe;
use super::Request;
use super::evidence::classify_response;
use super::plan::packet::sent_probe_matches;

pub(super) const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.scan_executor",
    "use one correlated probe per scan batch and retain at least one response",
);

/// The bounds one rolling probe window runs under.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PipelineOptions {
    pub(crate) max_in_flight: usize,
    pub(crate) probes_per_second: Option<u32>,
    pub(crate) max_duration: Duration,
    pub(crate) max_prepared_bytes: usize,
    pub(crate) max_evidence_frames: usize,
    pub(crate) max_evidence_bytes: usize,
    pub(crate) max_undecoded: usize,
}

/// What a rolling probe window reports while it runs, keyed by the index of
/// the batch it concerns.
#[derive(Clone, Debug)]
pub(crate) enum PipelineEvent {
    Sent {
        index: usize,
        sent: Arc<SentPacket>,
    },
    Completed {
        index: usize,
        execution: Execution,
    },
    Undecoded {
        frame: packetcraftr_core::frame::Frame,
    },
    Diagnostic(packetcraftr_core::diagnostic::Diagnostic),
}

/// The capability to run scan batches as one rolling window of overlapping
/// probes instead of one exchange at a time. The engine uses it only when a
/// request asks for more than one probe in flight.
pub(crate) trait Pipelined: Executor<Batch<Probe>> {
    /// Runs every batch, keeping at most `options.max_in_flight` probes
    /// waiting for a response at once, and reports each send, completion,
    /// undecoded frame, and diagnostic through `emit` as it happens.
    fn execute_pipeline(
        &mut self,
        batches: &[Batch<Probe>],
        options: PipelineOptions,
        emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError>;
}

/// Runs a scan's batches on a client. The request's UDP profiles bind their
/// ports in an operation-local registry; the executor builds it once, on its
/// first batch, and keeps one view of the client that uses it.
pub(crate) struct ClientExecutor<'c, P, K> {
    client: &'c Client<P, K>,
    bindings: Vec<(u16, packetcraftr_core::layer::Id)>,
    configured: Option<Client<P, K>>,
    send: crate::send::Options,
    collection: crate::exchange::Collection,
}

impl<'c, P: Providers, K: Clock> ClientExecutor<'c, P, K> {
    pub(crate) fn new(client: &'c Client<P, K>, request: &Request) -> Self {
        Self {
            client,
            bindings: registry::bindings(request),
            configured: None,
            send: crate::send::Options {
                destination: None,
                plan: request.route.clone(),
                build: packetcraftr_core::build::Options::default(),
                allow_permissive_live: false,
            },
            collection: request.collection.clone(),
        }
    }

    /// The exchange executor over the client view with the configured
    /// registry, building that view on first use.
    fn exchange(&mut self) -> Result<ExchangeExecutor<'_, P, K>, BoundaryError> {
        let client = match &mut self.configured {
            Some(client) => client,
            configured => {
                let registry: Arc<Registry> =
                    registry::configured(self.client.registry(), &self.bindings)?;
                configured.insert(self.client.view_with_registry(registry))
            }
        };
        Ok(ExchangeExecutor::new(
            client,
            self.send.clone(),
            self.collection.clone(),
        ))
    }
}

impl<P: Providers, K: Clock> Executor<Batch<Probe>> for ClientExecutor<'_, P, K> {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Execution, BoundaryError> {
        let first = batch.probe()?;
        let packet = first.packet();
        if !sent_probe_matches(first, &packet) {
            return Err(EXECUTOR_FAULT.invalid("scan packet does not match its correlated probe"));
        }
        let executor = self.exchange()?;
        let template = packetcraftr_core::template::Template::new(packet);
        let mut matches_request =
            |request_index: usize,
             sent: &packetcraftr_core::packet::Packet,
             response: &packetcraftr_core::decode::DecodedPacket| {
                request_index == 0
                    && classify_response(
                        executor.client.registry(),
                        first.endpoint.transport(),
                        sent,
                        response,
                    )
                    .is_some()
            };
        let exchange = executor.exchange_for_workflow(
            template,
            WorkflowOverrides {
                timeout: batch.timeout,
                max_template_packets: 1,
                destination: first.address,
                max_responses: None,
            },
            &mut matches_request,
            None,
        )?;
        Ok(Execution::from_exchange(batch.permit, exchange))
    }
}

impl<P: Providers, K: Clock> Pipelined for ClientExecutor<'_, P, K> {
    fn execute_pipeline(
        &mut self,
        batches: &[Batch<Probe>],
        options: PipelineOptions,
        emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError> {
        pipeline::run(&self.exchange()?, batches, options, emit)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use packetcraftr_core::error::Classified as _;

    use super::*;
    use crate::evidence::ExecutionPermit;
    use crate::probe::Transport;
    use crate::scan::Limits;
    use crate::target::{Family, Target};
    use crate::test_support::fake_client;

    #[test]
    fn a_batch_without_exactly_one_probe_is_rejected_before_any_provider_call() {
        let (client, providers) = fake_client();
        let request = Request {
            max_in_flight: 1,
            targets: Target::Address("192.0.2.2".parse().unwrap()).into(),
            transport: Transport::Tcp,
            udp_payload: bytes::Bytes::new(),
            udp_profiles: Default::default(),
            address_family: Family::Any,
            ports: vec![80],
            attempts: 1,
            timeout: Duration::from_millis(20),
            probes_per_second: None,
            limits: Limits::default(),
            route: Default::default(),
            collection: Default::default(),
        };
        let reshaped = Batch {
            probes: Vec::new(),
            timeout: request.timeout,
            permit: ExecutionPermit::new(),
            sequence: 0,
        };

        let error = ClientExecutor::new(&client, &request)
            .execute(&reshaped)
            .expect_err("a scan batch without its probe must be rejected");

        assert_eq!(error.classification().code, "cli.scan_executor");
        assert!(providers.calls().is_empty());
    }
}
