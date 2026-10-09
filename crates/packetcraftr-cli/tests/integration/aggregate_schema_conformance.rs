// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};

use packetcraftr::route::Plan;
use packetcraftr_cli::output::contract::Command;
use packetcraftr_cli::output::envelope::{Envelope, Published};
use packetcraftr_cli::output::{
    build as build_output, network as network_output, plan as plan_output,
};
use packetcraftr_core::build;
use packetcraftr_core::codec;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::packet::{MacAddress, VlanKind, VlanTag};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::link::Capability;
use packetcraftr_netio::link::Mode as LinkMode;
use packetcraftr_netio::route::Decision;
use packetcraftr_netio::route::Scope;
use packetcraftr_netio::route::SelectionReason;
use serde_json::Value;

use crate::common;

use common::schema_validator;

fn envelope<T: serde::Serialize>(
    command: Command,
    payload: T,
    diagnostics: Vec<Diagnostic>,
) -> Value {
    serde_json::to_value(Envelope::success(command, payload, diagnostics))
        .expect("aggregate envelope serializes")
}

fn published<T: serde::Serialize>(command: Command, published: Published<T>) -> Value {
    serde_json::to_value(Envelope::published(command, published))
        .expect("aggregate envelope serializes")
}

fn diagnostic() -> Diagnostic {
    let mut diagnostic = Diagnostic::warning("fixture.conformance", "representative warning");
    diagnostic.layer = Some(0);
    diagnostic.field = Some("length");
    diagnostic
}

fn udp_packet() -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 40_000,
        destination_port: 8_080,
        ..Udp::default()
    });
    packet.push(Raw::new(b"payload".to_vec()));
    packet
}

fn built_packet() -> build::BuiltPacket {
    build::Builder::new(builtin::registry())
        .build(
            udp_packet(),
            codec::Context::default(),
            build::Options::default(),
        )
        .expect("representative packet builds")
}

fn route_decision() -> Decision {
    Decision {
        interface: InterfaceId {
            name: "eth0".to_owned(),
            index: 3,
        },
        source_mac: Some(MacAddress([0, 1, 2, 3, 4, 5])),
        selected_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        preferred_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254))),
        selection_reason: SelectionReason::Gateway,
        destination_scope: Scope::Private,
        mtu: 1_500,
        capability: Capability::Layer2AndLayer3,
        link_type: LinkType::ETHERNET,
    }
}

fn route_plan() -> Plan {
    Plan {
        decision: route_decision(),
        mode: LinkMode::Layer2,
        lookup_destination: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
        final_destination: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
        visited_destinations: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))],
        packet_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        neighbor_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        neighbor_target: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254))),
        destination_mac: Some(MacAddress([6, 7, 8, 9, 10, 11])),
        source_mac: Some(MacAddress([0, 1, 2, 3, 4, 5])),
        neighbor_vlan_tags: vec![VlanTag {
            kind: VlanKind::Ieee8021Q,
            priority: 5,
            drop_eligible: true,
            vlan_id: 42,
        }],
        synthesized_ethernet: true,
    }
}

fn build_case() -> Value {
    let mut built = built_packet();
    built.diagnostics.push(diagnostic());
    published(
        Command::Build,
        Published::<build_output::Report>::from(built),
    )
}

fn plan_case() -> Value {
    envelope(
        Command::Plan,
        plan_output::Report {
            plan: network_output::Plan::from(route_plan()),
        },
        Vec::new(),
    )
}

#[test]
fn unknown_envelope_invalid_payload_reject() {
    for (pointer, value) in [
        ("/undeclared", Value::from(1)),
        ("/result/route", Value::from("invalid route")),
    ] {
        let mut document = plan_case();
        let (parent, key) = pointer.rsplit_once('/').expect("JSON pointer");
        document.pointer_mut(parent).expect("parent exists")[key] = value;
        assert!(
            schema_validator().validate(&document).is_err(),
            "invalid value at {pointer} must fail validation"
        );
    }

    let mut document = plan_case();
    document["result"].as_object_mut().unwrap().remove("route");
    assert!(schema_validator().validate(&document).is_err());

    let mut document = build_case();
    document["result"]["packet"]["undeclared"] = Value::from(1);
    assert!(schema_validator().validate(&document).is_err());
}

fn trace_plan() -> packetcraftr_cli::output::traceroute::hosts::Plan {
    use packetcraftr_cli::output::traceroute::hosts::{Plan, ReusePlan, StrategyPlan};
    Plan {
        first_hop: 1,
        max_hops: 30,
        attempts: 1,
        max_probes: 4096,
        strategy: Some(StrategyPlan {
            strategy: packetcraftr::probe::Transport::Tcp,
            destination_port: Some(443),
        }),
        reuse: Some(ReusePlan {
            max_age: std::time::Duration::from_secs(30),
        }),
    }
}

#[test]
fn scan_traceroute_member_matches_the_published_schema() {
    use packetcraftr_cli::output::traceroute::hosts::Report;

    let mut document: Value = serde_json::from_str(include_str!(
        "../../../../examples/documents/output-scan-success.json"
    ))
    .expect("published scan example must parse");
    let report =
        Report::new(trace_plan(), common::trace_hosts::aggregate()).expect("a representable trace");
    let member = serde_json::to_value(&report).expect("the trace serializes");
    document["result"]["traceroute"] = member.clone();
    schema_validator()
        .validate(&document)
        .unwrap_or_else(|error| panic!("the trace member must match the schema: {error}"));

    let statuses: Vec<_> = member["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|host| host["status"].as_str().unwrap())
        .collect();
    assert_eq!(
        statuses,
        [
            "complete",
            "complete",
            "incomplete",
            "not_traced",
            "not_traced"
        ]
    );
    assert_eq!(member["hosts"][0]["selection"]["basis"], "observed");
    assert_eq!(
        member["hosts"][0]["selection"]["observation"]["reply"],
        "tcp_syn_ack"
    );
    assert_eq!(member["hosts"][1]["selection"]["basis"], "requested");
    assert_eq!(member["hosts"][1]["reused_hops"][0]["source"], "192.0.2.10");
    assert_eq!(member["hosts"][4]["reason"], "scoped_target");
    assert_eq!(member["hosts"][4]["scope"]["zone"], "eth0");

    for (pointer, value) in [
        ("/hosts/0/completion", Value::from("timeout")),
        ("/hosts/3/completion", Value::from("timeout")),
        ("/hosts/0/selection/basis", Value::from("guessed")),
        ("/hosts/1/reused_hops/0/age", Value::from("long")),
    ] {
        let mut invalid = document.clone();
        let (parent, key) = pointer.rsplit_once('/').expect("JSON pointer");
        invalid["result"]["traceroute"]
            .pointer_mut(parent)
            .expect("parent exists")[key] = value;
        assert!(
            schema_validator().validate(&invalid).is_err(),
            "{pointer} must fail validation"
        );
    }
}
