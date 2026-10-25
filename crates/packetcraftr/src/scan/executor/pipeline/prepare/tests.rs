// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::{
    engine::operation::Operation,
    scan::{Probe, Stage},
    target::ResolvedZone,
};
use std::{sync::Arc, time::Duration};

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
fn route_map_scope_source_table_and_materialized_names_have_distinct_charges() {
    let client = crate::engine::preparation::tests::client_for_plan();
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
    let options = PipelineOptions {
        max_in_flight: 1,
        probes_per_second: None,
        max_duration: Duration::from_secs(10),
        control: deadline.clone(),
        max_prepared_bytes: 8 * 1024 * 1024,
        max_evidence_frames: 100,
        max_evidence_bytes: 1024 * 1024,
        preceding: Default::default(),
    };
    let address = "10.0.0.1".parse().unwrap();
    let plain = probe(0, address, None);
    let scoped = probe(
        0,
        address,
        Some(ResolvedZone {
            zone: "controlled0".parse().unwrap(),
            interface: interface::Id {
                index: 1,
                name: "controlled0".to_owned(),
            },
        }),
    );
    let end = client.now() + Duration::from_secs(10);
    let plain_plan = plan(
        &executor,
        &[Planned { probe: &plain }],
        &options,
        end,
        &deadline,
        false,
    )
    .unwrap();
    let scoped_plan = plan(
        &executor,
        &[Planned { probe: &scoped }],
        &options,
        end,
        &deadline,
        false,
    )
    .unwrap();
    let source_name = &plain_plan.interfaces[0].name;
    assert_eq!(
        plain_plan.interfaces_bytes,
        256 + std::mem::size_of::<interface::Id>() + source_name.capacity()
    );
    assert_eq!(scoped_plan.interfaces_bytes, plain_plan.interfaces_bytes);
    let scoped_bytes = scoped.scope.as_ref().unwrap().retained_bytes();
    assert_eq!(
        scoped_plan.base_bytes - plain_plan.base_bytes,
        scoped_bytes + 2 * source_name.len(),
        "declared scope, owned map key and AuthorizedRoute scope are separate"
    );
    assert_eq!(
        scoped_plan.probes[0].memory - plain_plan.probes[0].memory,
        source_name.len(),
        "fresh scoped planning needs one temporary selector clone"
    );
    let route = plain_plan.routes.values().next().unwrap();
    assert_eq!(route_charge(route), 2048 + source_name.capacity());
}

#[test]
fn optional_previews_preserve_the_minimum_admitted_resource_profile() {
    assert!(
        std::mem::size_of::<AdmittedProbe>() + 2 * std::mem::size_of::<usize>() <= 384,
        "descriptor charge covers preview handle and bounded eviction-stack capacity"
    );
    for hosts in [1, 8] {
        let mut client = crate::engine::preparation::tests::client_for_plan();
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
                    None,
                )
            })
            .collect();
        let planned: Vec<_> = probes.iter().map(|probe| Planned { probe }).collect();
        let mut options = PipelineOptions {
            max_in_flight: 4,
            probes_per_second: None,
            max_duration: Duration::from_secs(10),
            control: deadline.clone(),
            max_prepared_bytes: 8 * 1024 * 1024,
            max_evidence_frames: 100,
            max_evidence_bytes: 1024 * 1024,
            preceding: Default::default(),
        };
        let plan_end = client.now() + Duration::from_secs(10);
        let baseline = plan(&executor, &planned, &options, plan_end, &deadline, false).unwrap();
        let base = baseline.base_bytes;
        let maximum = baseline
            .probes
            .iter()
            .map(|probe| probe.memory)
            .max()
            .unwrap();
        drop(baseline);
        for retained_capacity in [0, 2] {
            options.max_prepared_bytes = base + (retained_capacity + 1) * maximum;
            let retained = plan(&executor, &planned, &options, plan_end, &deadline, true)
                .expect("optional cache must fit the admitted profile");
            assert_eq!(
                retained
                    .probes
                    .iter()
                    .filter(|probe| probe.retained.is_some())
                    .count(),
                retained_capacity
            );
            assert_eq!(retained.base_bytes, base + retained_capacity * maximum);
            assert!(retained.base_bytes + maximum <= options.max_prepared_bytes);
        }
    }
}
