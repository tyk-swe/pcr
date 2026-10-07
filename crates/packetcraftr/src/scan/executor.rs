// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod pipeline;
mod registry;

pub(super) use pipeline::limit;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::execution::{ExchangeExecutor, Executor, ExecutorFault, WorkflowOverrides};
use crate::probe::{Batch, Evidence};
use crate::providers::PacketProviders;
use crate::{Client, Stats, evidence::SentPacket};
use packetcraftr_core::error::BoundaryError;

use super::Probe;
use super::Request;
use super::evidence::classify_response;
use super::plan::packet::sent_probe_matches;

pub(super) const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.scan_executor",
    "use one correlated probe per scan batch and retain at least one response",
);

#[derive(Clone, Copy, Debug)]
pub(crate) struct PipelineOptions {
    pub(crate) max_in_flight: usize,
    pub(crate) probes_per_second: Option<u32>,
    pub(crate) max_duration: Duration,
    pub(crate) max_prepared_bytes: usize,
    pub(crate) max_evidence_frames: usize,
    pub(crate) max_evidence_bytes: usize,
}

#[derive(Clone, Debug)]
pub(crate) enum PipelineEvent {
    Sent {
        index: usize,
        sent: Arc<SentPacket>,
    },
    Completed {
        index: usize,
        execution: Evidence,
    },
    Undecoded {
        frame: packetcraftr_core::frame::Frame,
    },
    /// A correlated frame no probe outcome carries.
    Unattributed {
        frame: packetcraftr_core::frame::Frame,
        attribution: crate::scan::Attribution,
        sequence: Option<u64>,
    },
    Diagnostic(packetcraftr_core::diagnostic::Diagnostic),
}

pub(crate) trait Pipelined: Executor<Batch<Probe>> {
    fn execute_pipeline(
        &mut self,
        batches: &[Batch<Probe>],
        options: PipelineOptions,
        emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError>;
}

pub(crate) struct ClientExecutor<'c, P, K> {
    client: &'c Client<P, K>,
    bindings: Vec<(u16, packetcraftr_core::layer::Id)>,
    configured: Option<Client<P, K>>,
    send: crate::send::Options,
    collection: crate::exchange::Collection,
}

impl<'c, P: PacketProviders, K: Clock> ClientExecutor<'c, P, K> {
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

impl<P: PacketProviders, K: Clock> Executor<Batch<Probe>> for ClientExecutor<'_, P, K> {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
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
                interface: first.scope.as_ref().map(|scope| scope.interface.clone()),
                max_responses: None,
            },
            &mut matches_request,
            None,
        )?;
        Ok(Evidence::from_exchange(batch.permit, exchange))
    }
}

impl<P: PacketProviders, K: Clock> Pipelined for ClientExecutor<'_, P, K> {
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
    use crate::scan::Limits;
    use crate::target::{Family, Target};
    use crate::test_support::fake_client;

    #[test]
    fn a_batch_without_exactly_one_probe_is_rejected_before_any_provider_call() {
        let (client, providers) = fake_client();
        let request = Request {
            target_sources: Vec::new(),
            max_in_flight: 1,
            targets: Target::Address("192.0.2.2".parse().unwrap()).into(),
            udp_payload: bytes::Bytes::new(),
            udp_profiles: Default::default(),
            address_family: Family::Any,
            endpoints: vec![crate::probe::ProbeEndpoint::Tcp { port: 80 }],
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
