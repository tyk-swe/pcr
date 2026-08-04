// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    AggregateOutput, CommandName, ExchangeCommandResult, FrameOutput, InterfaceCapability,
    InterfaceFlags, InterfaceId, InterfaceOutput, InterfacesCommandResult, LinkMode,
    MaterializedRouteOutput, PlanCommandResult, ReadFrameCommandResult, ReplayFrameCommandResult,
    RoutesCommandResult, SendCommandResult, StreamRecord, WireFrameOutput, exact_frame, json_file,
    operation_stats, planned_route, route_decision,
};

#[test]
fn published_route_and_live_success_outputs_match_typed_contracts() {
    let plan = AggregateOutput::success(
        CommandName::Plan,
        PlanCommandResult {
            route: planned_route().into(),
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(plan).unwrap(),
        json_file("output-plan-success.json")
    );

    let routes = AggregateOutput::success(
        CommandName::Routes,
        RoutesCommandResult {
            routes: vec![route_decision().into()],
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(routes).unwrap(),
        json_file("output-routes-success.json")
    );

    let interfaces = AggregateOutput::success(
        CommandName::Interfaces,
        InterfacesCommandResult {
            interfaces: vec![InterfaceOutput {
                name: "lab0".to_owned(),
                index: 2,
                description: Some("isolated test interface".to_owned()),
                mac: Some("02:00:00:00:00:01".to_owned()),
                addresses: vec!["192.168.56.2/24".to_owned()],
                flags: InterfaceFlags {
                    up: true,
                    broadcast: true,
                    loopback: false,
                    point_to_point: false,
                    multicast: true,
                },
                mtu: Some(1500),
                capability: InterfaceCapability::Layer2And3,
                link_type: 1,
            }],
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(interfaces).unwrap(),
        json_file("output-interfaces-success.json")
    );

    let send = AggregateOutput::success(
        CommandName::Send,
        SendCommandResult {
            frame: WireFrameOutput::new(vec![0xde, 0xad, 0xbe, 0xef]),
            route: MaterializedRouteOutput {
                plan: planned_route().into(),
                neighbor: None,
            },
        },
        Vec::new(),
    )
    .with_stats(operation_stats());
    assert_eq!(
        serde_json::to_value(send).unwrap(),
        json_file("output-send-success.json")
    );

    let exchange = AggregateOutput::success(
        CommandName::Exchange,
        ExchangeCommandResult {
            sent: vec![WireFrameOutput::new(vec![0xde, 0xad, 0xbe, 0xef])],
            responses: Vec::new(),
            unanswered: vec![0],
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
        },
        Vec::new(),
    )
    .with_stats(operation_stats());
    assert_eq!(
        serde_json::to_value(exchange).unwrap(),
        json_file("output-exchange-success.json")
    );
}

#[test]
fn published_read_and_replay_stream_events_match_typed_contracts() {
    let read = StreamRecord::success(
        CommandName::Read,
        0,
        ReadFrameCommandResult::try_from_frame(exact_frame()).unwrap(),
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(read).unwrap(),
        json_file("output-read-event.json")
    );

    let replay = StreamRecord::success(
        CommandName::Replay,
        0,
        ReplayFrameCommandResult {
            source_sequence: 0,
            interface: InterfaceId {
                name: "lab0".to_owned(),
                index: 2,
            }
            .into(),
            link_mode: LinkMode::Auto.into(),
            scheduled_delay: std::time::Duration::ZERO,
            bytes_sent: 4,
            frame: FrameOutput::try_from_frame(exact_frame()).unwrap(),
            transmitted: true,
        },
        Vec::new(),
    );
    assert_eq!(
        serde_json::to_value(replay).unwrap(),
        json_file("output-replay-event.json")
    );
}
