// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::{
    engine::operation::Operation,
    scan::{Probe, Stage},
    target::ResolvedZone,
};
use packetcraftr_core::{
    decode,
    frame::{Frame, LinkType},
    layer::Raw,
    protocol::{builtin, network::Ipv4, transport::Udp},
};
use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

fn probe(sequence: u64, address: IpAddr, scope: Option<ResolvedZone>) -> Probe {
    Probe {
        sequence,
        stage: Stage::Scan,
        address,
        scope,
        endpoint: crate::probe::Endpoint::Udp { port: 9 },
        tcp_scan: Default::default(),
        sctp_scan: Default::default(),
        attempt: 1,
        udp_payload: vec![7; 64].into(),
        udp_profile: None,
    }
}

#[test]
fn scoped_and_unscoped_previews_obey_budget_and_materialize_every_probe() {
    for (hosts, scoped, name, budget, should_admit) in [
        (1, false, "controlled0".to_owned(), 128 * 1024, true),
        (1, true, "controlled0".to_owned(), 128 * 1024, true),
        (8, false, "controlled0".to_owned(), 128 * 1024, true),
        (8, true, "controlled0".to_owned(), 128 * 1024, true),
        (4, false, "controlled0".to_owned(), 256 * 1024, true),
        (4, false, "x".repeat(65536), 256 * 1024, false),
    ] {
        let mut client = crate::engine::preparation::tests::client_for_plan(&name);
        Arc::make_mut(&mut client.policy)
            .allowed_destinations
            .clear();
        let operation = Operation::new(&client, Duration::from_secs(10));
        let deadline = operation.deadline(&client, Duration::from_secs(10));
        let executor = WorkflowExecutor::new(
            &client,
            &operation,
            crate::send::Options {
                plan: crate::route::Options {
                    link_mode: packetcraftr_netio::link::Mode::Layer3,
                    ..Default::default()
                },
                ..Default::default()
            },
            Default::default(),
        );
        let probes: Vec<_> = (0..8)
            .map(|sequence| {
                probe(
                    sequence,
                    format!("10.0.0.{}", sequence as usize % hosts + 1)
                        .parse()
                        .unwrap(),
                    scoped.then(|| ResolvedZone {
                        zone: "controlled0".parse().unwrap(),
                        interface: interface::Id {
                            index: 1,
                            name: "controlled0".to_owned(),
                        },
                    }),
                )
            })
            .collect();
        let planned: Vec<_> = probes.iter().map(|probe| Planned { probe }).collect();
        let options = PipelineOptions {
            max_in_flight: 4,
            probes_per_second: None,
            max_duration: Duration::from_secs(10),
            control: deadline.clone(),
            max_prepared_bytes: budget,
            max_evidence_frames: 100,
            max_evidence_bytes: 1024 * 1024,
            preceding: Default::default(),
        };
        let end = client.now() + Duration::from_secs(10);
        for retain in [false, true] {
            let tiny = PipelineOptions {
                max_prepared_bytes: 1,
                ..options.clone()
            };
            assert!(plan(&executor, &planned, &tiny, end, &deadline, retain).is_err());
            let result = plan(&executor, &planned, &options, end, &deadline, retain);
            if !should_admit {
                assert!(result.is_err());
                continue;
            }
            let accepted = result.unwrap();
            assert_eq!(accepted.probes.len(), probes.len());
            for (probe, admitted) in probes.iter().zip(accepted.probes) {
                let key = (
                    probe.address,
                    probe.scope.as_ref().map(|scope| scope.interface.clone()),
                );
                let route = &accepted.routes[&key];
                let prepared = match admitted.retained {
                    Some(retained) => {
                        accepted
                            .admission
                            .materialize_retained(retained, route, admitted.cost)
                    }
                    None => accepted
                        .admission
                        .rebuild(probe.packet(), route, admitted.cost),
                }
                .unwrap();
                let frame =
                    Frame::new(UNIX_EPOCH, LinkType::RAW, prepared.built().bytes.clone()).unwrap();
                let decoded = decode::Dissector::new(builtin::registry())
                    .decode(frame, Default::default())
                    .unwrap();
                assert_eq!(
                    IpAddr::V4(decoded.packet.get::<Ipv4>().unwrap().destination),
                    probe.address
                );
                assert_eq!(decoded.packet.get::<Udp>().unwrap().destination_port, 9);
                assert_eq!(
                    decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
                    &[7; 64]
                );
            }
        }
    }
}
