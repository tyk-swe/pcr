use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::engine::{build_batches, sent_traceroute_probe_matches};
use super::super::*;
use super::support::{CountingRejectExecutor, FixedAuthorizer, NoopClock, udp_traceroute_request};
use crate::protocol::builtin::registry as default_registry;

#[test]
fn udp_destination_port_overflow_is_rejected_before_authorized_probe_construction() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut operation = udp_traceroute_request(Target::Address(destination));
    operation.destination_port = Some(u16::MAX);
    let mut authorizer = FixedAuthorizer {
        address: destination,
        operations: Vec::new(),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let error = traceroute(
        &operation,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut CountingRejectExecutor(Arc::clone(&calls)),
        &mut NoopClock::default(),
    )
    .unwrap_err();
    assert!(matches!(error, TracerouteError::InvalidPort { .. }));
    assert!(authorizer.operations.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn udp_and_tcp_traceroute_reject_zero_destination_ports() {
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    for strategy in [TracerouteStrategy::Udp, TracerouteStrategy::Tcp] {
        let mut request = udp_traceroute_request(Target::Address(destination));
        request.strategy = strategy;
        request.destination_port = Some(0);

        assert!(matches!(
            request.validate(),
            Err(TracerouteError::InvalidPort { message })
                if message == "UDP and TCP traceroute require a non-zero destination port"
        ));
    }
}

#[test]
fn generated_hop_batches_share_network_identity_and_preserve_every_attempt() {
    for destination in [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
        IpAddr::V6("fd00::9".parse().unwrap()),
    ] {
        let mut request = udp_traceroute_request(Target::Address(destination));
        request.probes_per_hop = 3;
        let batches = build_batches(&request, destination).unwrap();
        assert_eq!(batches.len(), 2);

        for batch in &batches {
            assert_eq!(batch.probes.len(), 3);
            assert!(
                batch
                    .probes
                    .iter()
                    .all(|probe| sent_traceroute_probe_matches(probe, &probe.packet()))
            );
        }

        match destination {
            IpAddr::V4(_) => {
                let first = batches[0].probes[0].packet();
                let second = batches[1].probes[0].packet();
                let first_id = first.get::<Ipv4>().unwrap().identification;
                assert!(
                    batches[0].probes.iter().all(|probe| probe
                        .packet()
                        .get::<Ipv4>()
                        .unwrap()
                        .identification
                        == first_id)
                );
                assert_ne!(second.get::<Ipv4>().unwrap().identification, first_id);
            }
            IpAddr::V6(_) => {
                let first = batches[0].probes[0].packet();
                let second = batches[1].probes[0].packet();
                let first_flow_label = first.get::<Ipv6>().unwrap().flow_label;
                assert!(
                    batches[0].probes.iter().all(|probe| probe
                        .packet()
                        .get::<Ipv6>()
                        .unwrap()
                        .flow_label
                        == first_flow_label)
                );
                assert_ne!(second.get::<Ipv6>().unwrap().flow_label, first_flow_label);
            }
        }
    }
}
