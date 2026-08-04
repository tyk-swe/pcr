// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use packetcraftr::{
    capture::{
        Direction as CaptureDirection, Format as CaptureFileFormat, Frame as CapturedFrame,
        LinkType,
    },
    net::{
        interface::Id as InterfaceId,
        link::{Capability as LinkCapability, MacAddress, Mode as LinkMode},
        neighbor::{VlanKind as NeighborVlanKind, VlanTag as NeighborVlanTag},
        route::{
            Decision as RouteDecision, Plan as PlannedRoute, Scope as DestinationScope,
            SelectionReason as RouteSelectionReason,
        },
    },
    output::{
        capture::{
            Event as CaptureFrameCommandResult, Frame as FrameOutput, Timestamp as OutputTimestamp,
        },
        contract::{CONTRACTS as COMMAND_OUTPUT_CONTRACTS, Command as CommandName},
        dns::{
            Attempt as DnsAttemptOutput, AttemptStatus as DnsAttemptStatus,
            Event as DnsStreamCommandResult, Outcome as DnsOutcome, Record as DnsRecordOutput,
            RecordData as DnsRecordData, RejectedRecord as DnsRejectedRecordOutput,
            Result as DnsCommandResult, Section as DnsSection,
        },
        envelope::{
            Aggregate as AggregateOutput, CaptureStats as CaptureStatistics,
            Stats as OperationStats, Stream as StreamRecord,
        },
        exchange::{Event as ExchangeStreamCommandResult, Result as ExchangeCommandResult},
        interfaces::{
            Capability as InterfaceCapability, Flags as InterfaceFlags,
            Interface as InterfaceOutput, Result as InterfacesCommandResult,
        },
        plan::Result as PlanCommandResult,
        read::Result as ReadFrameCommandResult,
        replay::{Frame as ReplayFrameCommandResult, Result as ReplayCommandResult},
        routes::Result as RoutesCommandResult,
        scan::{
            Classification as ScanClassification, Event as ScanStreamCommandResult,
            Evidence as ProbeEvidenceOutput, Port as ScanPortOutput,
            ProbeStatus as ScanProbeStatus, Result as ScanCommandResult,
        },
        send::{
            MaterializedRoute as MaterializedRouteOutput, Result as SendCommandResult,
            Wire as WireFrameOutput,
        },
        traceroute::{
            Completion as TraceCompletionReason, Event as TracerouteStreamCommandResult,
            Hop as TraceHopOutput, Probe as TraceProbeOutput, ProbeStatus as TraceProbeStatus,
            ResponseKind as TraceResponseKind, Result as TracerouteCommandResult,
        },
    },
    packet::diagnostic::Diagnostic,
    workflow::replay::{Summary as ReplaySummary, Timing as ReplayTiming},
};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/documents")
        .join(name)
}

fn json_file(name: &str) -> serde_json::Value {
    serde_json::from_slice(&fs::read(example(name)).unwrap()).unwrap()
}

fn route_decision() -> RouteDecision {
    RouteDecision {
        interface: InterfaceId {
            name: "lab0".to_owned(),
            index: 2,
        },
        source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
        selected_address: Some("192.168.56.2".parse().unwrap()),
        preferred_source: None,
        next_hop: Some("192.168.56.1".parse().unwrap()),
        selection_reason: RouteSelectionReason::Gateway,
        destination_scope: DestinationScope::Private,
        mtu: 1500,
        capability: LinkCapability::Layer2And3,
        link_type: LinkType::ETHERNET,
    }
}

fn planned_route() -> PlannedRoute {
    PlannedRoute {
        route: route_decision(),
        mode: LinkMode::Layer2,
        lookup_destination: Some("192.168.56.9".parse().unwrap()),
        final_destination: Some("192.168.56.9".parse().unwrap()),
        visited_destinations: vec!["192.168.56.9".parse().unwrap()],
        packet_source: Some("192.168.56.2".parse().unwrap()),
        neighbor_source: Some("192.168.56.2".parse().unwrap()),
        neighbor_target: Some("192.168.56.1".parse().unwrap()),
        destination_mac: Some(MacAddress([2, 0, 0, 0, 0, 2])),
        source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
        neighbor_vlan_tags: vec![NeighborVlanTag {
            kind: NeighborVlanKind::Ieee8021Q,
            priority: 0,
            drop_eligible: false,
            vlan_id: 42,
        }],
        synthesized_ethernet: true,
    }
}

fn operation_stats() -> OperationStats {
    OperationStats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 4,
        elapsed: std::time::Duration::ZERO,
        capture: CaptureStatistics::default(),
    }
}

fn exact_frame() -> CapturedFrame {
    CapturedFrame::new(
        std::time::UNIX_EPOCH,
        LinkType(147),
        vec![0xde, 0xad, 0xbe, 0xef],
    )
    .unwrap()
}

fn packet_protocols(value: &serde_json::Value) -> Vec<&str> {
    value["result"]["packet"]["layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|layer| layer["protocol"].as_str().unwrap())
        .collect()
}

fn assert_gre_sctp_example(value: &serde_json::Value) {
    assert_eq!(
        packet_protocols(value),
        ["ipv4", "gre", "ipv6", "sctp", "raw"]
    );
    assert_eq!(
        value["result"]["packet"]["layers"][0]["fields"]["protocol"]["value"],
        47
    );
    assert_eq!(
        value["result"]["packet"]["layers"][1]["fields"]["protocol_type"]["value"],
        0x86dd
    );
    assert_eq!(
        value["result"]["packet"]["layers"][2]["fields"]["next_header"]["value"],
        132
    );
    assert_eq!(
        value["result"]["packet"]["layers"][3]["fields"]["checksum"]["type"],
        "unsigned"
    );
    assert_eq!(
        value["result"]["layout"]["layers"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
}

fn assert_igmp_example(value: &serde_json::Value) {
    assert_eq!(packet_protocols(value), ["ipv4", "igmp"]);
    assert_eq!(
        value["result"]["packet"]["layers"][0]["fields"]["ttl"]["type"],
        "unsigned"
    );
    assert_eq!(
        value["result"]["packet"]["layers"][0]["fields"]["ttl"]["value"],
        1
    );
    assert_eq!(
        value["result"]["packet"]["layers"][0]["fields"]["protocol"]["value"],
        2
    );
    assert_eq!(
        value["result"]["packet"]["layers"][1]["fields"]["checksum"]["type"],
        "unsigned"
    );
}

mod contract_outputs;
mod live_outputs;
mod offline_outputs;
mod workflow_outputs;
