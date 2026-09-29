// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::execution::{ExchangeExecutor, Executor};
use crate::execution::{ExecutorFault, WorkflowOverrides};
use crate::probe::{Batch, Evidence, Transport};
use packetcraftr_core::error::BoundaryError;

use crate::clock::Clock;
use crate::providers::PacketProviders;

use super::Probe;
use super::evidence::classify_probe_response;

const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.traceroute_executor",
    "use homogeneous bounded hop batches and retain at least one response per probe",
);

impl<P: PacketProviders, K: Clock> Executor<Batch<Probe>> for ExchangeExecutor<'_, P, K> {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let first = validate_batch(batch)?;

        let template = probe_template(batch, first)?;

        let mut matches_request =
            |request_index: usize,
             sent: &packetcraftr_core::packet::Packet,
             response: &packetcraftr_core::decode::DecodedPacket| {
                batch.probes.get(request_index).is_some_and(|probe| {
                    classify_probe_response(self.client.registry(), probe, sent, response).is_some()
                })
            };
        let exchange = self.exchange_for_workflow(
            template,
            WorkflowOverrides {
                timeout: batch.timeout,
                max_template_packets: batch.probes.len(),
                destination: first.address,
                max_responses: None,
            },
            &mut matches_request,
            None,
        )?;
        let execution = Evidence::from_exchange(batch.permit, exchange);
        Ok(execution)
    }
}

fn probe_template(
    batch: &Batch<Probe>,
    first: &Probe,
) -> Result<packetcraftr_core::template::Template, BoundaryError> {
    let (varying_layer, varying_field) = match first.target.transport() {
        Transport::Udp if first.udp_port_mode == super::UdpPortMode::Fixed => (2, "bytes"),
        Transport::Udp => (1, "destination_port"),
        Transport::Tcp => (1, "sequence"),
        Transport::Icmp => (1, "body"),
    };
    let mut template = packetcraftr_core::template::Template::new(first.packet());
    if batch.probes.len() > 1 {
        let values = batch
            .probes
            .iter()
            .map(|probe| {
                probe
                    .packet()
                    .iter()
                    .nth(varying_layer)
                    .and_then(|layer| layer.field(varying_field))
                    .ok_or_else(|| {
                        EXECUTOR_FAULT.invalid(format!(
                            "{} probe has no {varying_field} correlation field",
                            probe.target.transport()
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        template = template.axis(varying_layer, varying_field, values);
    }

    Ok(template)
}

fn validate_batch(batch: &Batch<Probe>) -> Result<&Probe, BoundaryError> {
    let first = batch
        .probes
        .first()
        .ok_or_else(|| EXECUTOR_FAULT.invalid("traceroute executor received an empty hop batch"))?;
    if batch
        .probes
        .iter()
        .any(|probe| probe.target.port() == Some(0))
    {
        return Err(EXECUTOR_FAULT.invalid("traceroute probes require a non-zero destination port"));
    }
    if batch
        .probes
        .iter()
        .any(|probe| probe.target.transport() != Transport::Icmp && probe.source_port == 0)
    {
        return Err(
            EXECUTOR_FAULT.invalid("UDP and TCP traceroute probes require a non-zero source port")
        );
    }
    if batch.probes.iter().any(|probe| {
        probe.address != first.address
            || probe.target.transport() != first.target.transport()
            || probe.source_port != first.source_port
            || probe.hop_limit != first.hop_limit
            || probe.cycle != first.cycle
            || probe.udp_port_mode != first.udp_port_mode
            || (probe.udp_port_mode == super::UdpPortMode::Fixed && probe.target != first.target)
            || (probe.target.transport() == Transport::Tcp && probe.target != first.target)
    }) {
        return Err(EXECUTOR_FAULT.invalid(
            "traceroute batches must share address, strategy, source port, hop limit, and TCP destination port",
        ));
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use super::*;
    use crate::evidence::ExecutionPermit;
    use crate::probe::ProbeEndpoint;

    fn batch(target: ProbeEndpoint, source_ports: &[u16]) -> Batch<Probe> {
        Batch {
            probes: source_ports
                .iter()
                .enumerate()
                .map(|(index, source_port)| Probe {
                    udp_port_mode: Default::default(),
                    cycle: 1,
                    sequence: u64::try_from(index).expect("test index fits u64"),
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    target,
                    hop_limit: 1,
                    attempt: u32::try_from(index).expect("test index fits u32"),
                    source_port: *source_port,
                })
                .collect(),
            timeout: Duration::from_secs(1),
            permit: ExecutionPermit::new(),
            sequence: 0,
        }
    }

    #[test]
    fn fixed_tuple_hop_templates_expand_every_distinct_token() {
        let mut batch = batch(
            ProbeEndpoint::Udp { port: 33_434 },
            &[49_152, 49_152, 49_152],
        );
        for probe in &mut batch.probes {
            probe.udp_port_mode = super::super::UdpPortMode::Fixed;
        }
        let template = probe_template(&batch, validate_batch(&batch).unwrap()).unwrap();
        let packets = template
            .expand(3)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for (packet, probe) in packets.iter().zip(&batch.probes) {
            assert!(super::super::plan::packet::sent_probe_matches(
                probe, packet
            ));
            assert_eq!(
                packet
                    .get::<packetcraftr_core::layer::Raw>()
                    .unwrap()
                    .bytes
                    .as_ref(),
                ((probe.sequence + 1) as u16).to_be_bytes()
            );
            assert_eq!(
                packet
                    .get::<packetcraftr_core::protocol::transport::Udp>()
                    .unwrap()
                    .destination_port,
                33_434
            );
        }
    }

    #[test]
    fn executor_rejects_heterogeneous_source_ports() {
        let batch = batch(ProbeEndpoint::Udp { port: 33_434 }, &[49_152, 49_153]);

        assert!(validate_batch(&batch).is_err());
    }

    #[test]
    fn executor_rejects_zero_transport_source_ports() {
        for target in [
            ProbeEndpoint::Udp { port: 33_434 },
            ProbeEndpoint::Tcp { port: 80 },
        ] {
            assert!(validate_batch(&batch(target, &[0])).is_err());
        }
        assert!(validate_batch(&batch(ProbeEndpoint::Icmp, &[0])).is_ok());
    }
}
