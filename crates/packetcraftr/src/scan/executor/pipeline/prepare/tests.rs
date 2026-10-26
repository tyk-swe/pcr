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
    assert!(scoped_plan.base_bytes > plain_plan.base_bytes);
    assert!(scoped_plan.probes[0].memory > plain_plan.probes[0].memory);
    let plain_route = plain_plan.routes.values().next().unwrap();
    let scoped_route = scoped_plan.routes.values().next().unwrap();
    assert!(route_charge(scoped_route) > route_charge(plain_route));
    assert_eq!(scoped_plan.interfaces, plain_plan.interfaces);
    assert_eq!(scoped_plan.interfaces_bytes, plain_plan.interfaces_bytes);
    let second = probe(1, address, None);
    let pair_plan = plan(
        &executor,
        &[Planned { probe: &plain }, Planned { probe: &second }],
        &options,
        end,
        &deadline,
        false,
    )
    .unwrap();
    assert!(pair_plan.interfaces_bytes > plain_plan.interfaces_bytes);
    assert!(pair_plan.base_bytes > plain_plan.base_bytes);
    drop(pair_plan);
    let plain_required = plain_plan.base_bytes
        + plain_plan
            .probes
            .iter()
            .map(|probe| probe.memory)
            .max()
            .unwrap();
    let scoped_required = scoped_plan.base_bytes
        + scoped_plan
            .probes
            .iter()
            .map(|probe| probe.memory)
            .max()
            .unwrap();
    assert!(scoped_required > plain_required);
    drop(plain_plan);
    drop(scoped_plan);
    let mut tight = options.clone();
    tight.max_prepared_bytes = plain_required;
    plan(
        &executor,
        &[Planned { probe: &plain }],
        &tight,
        end,
        &deadline,
        false,
    )
    .expect("unscoped probe fits its measured profile");
    assert!(
        plan(
            &executor,
            &[Planned { probe: &scoped }],
            &tight,
            end,
            &deadline,
            false,
        )
        .is_err()
    );
    tight.max_prepared_bytes = scoped_required;
    plan(
        &executor,
        &[Planned { probe: &scoped }],
        &tight,
        end,
        &deadline,
        false,
    )
    .expect("scoped probe fits its measured profile");
}

#[test]
fn optional_previews_preserve_the_minimum_admitted_resource_profile() {
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
        let mut previous_retained_base = None;
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
            assert!(retained.base_bytes + maximum <= options.max_prepared_bytes);
            assert!(retained.base_bytes >= base);
            if retained_capacity > 0 {
                assert!(retained.base_bytes > base);
            }
            if let Some(previous) = previous_retained_base {
                assert!(retained.base_bytes > previous);
            }
            previous_retained_base = Some(retained.base_bytes);
        }
    }
}
