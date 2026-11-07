// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr::{
    Sink, Stats,
    traceroute::{ResponseKind, Termination},
};
use packetcraftr_core::frame::{Frame, LinkType};
use serde_json::{Value, json};

#[test]
fn aggregate_and_stream_preserve_multipath_evidence() {
    let destination: IpAddr = "10.0.0.9".parse().unwrap();
    let flow = library::Flow {
        id: 1,
        source: "10.0.0.2".parse().unwrap(),
        destination,
        strategy: packetcraftr::probe::Transport::Udp,
        source_port: Some(49160),
        destination_port: Some(33434),
        icmp_identifier: None,
        ipv6_flow_label: None,
    };
    let rtt = library::Rtt {
        samples: 1,
        minimum: Duration::from_millis(2),
        median: Duration::from_millis(2),
        maximum: Duration::from_millis(2),
    };
    let keys = [
        library::NodeKey {
            hop_limit: 1,
            responder: "10.0.1.1".parse().unwrap(),
        },
        library::NodeKey {
            hop_limit: 2,
            responder: destination,
        },
    ];
    let edge = library::Edge {
        from: keys[0],
        to: keys[1],
        evidence: vec![[0, 1]],
    };
    let nodes = keys.map(|key| library::Node {
        key,
        rtt: rtt.clone(),
    });
    let completion = library::FlowCompletion {
        flow_id: 1,
        sweep: 1,
        completion: Termination::DestinationReached,
        last_hop: 2,
    };
    let topology = library::TopologyUpdate {
        nodes: nodes.to_vec(),
        edges: vec![edge.clone()],
        changes: vec![],
    };
    let summary = library::Summary {
        planned_probes: 2,
        probes_sent: 2,
        answered_probes: 2,
        replies_seen: 2,
        retained_evidence_bytes: 4104,
        sweeps_completed: 1,
        nodes: 2,
        edges: 1,
        ..Default::default()
    };
    let report = library::Report {
        target: destination.to_string(),
        resolved_addresses: vec![destination],
        destination,
        strategy: packetcraftr::probe::Transport::Udp,
        flows: vec![flow.clone()],
        flow_summaries: vec![library::FlowSummary {
            flow_id: 1,
            probes_sent: 2,
            answered_probes: 2,
            sweeps_reached: 1,
            destination_rtt: Some(rtt),
            ..Default::default()
        }],
        completions: vec![completion.clone()],
        topology,
        summary,
        stats: Stats {
            packets_attempted: 2,
            packets_completed: 2,
            bytes: 88,
            ..Default::default()
        },
    };
    let mut events = vec![library::Event::Flow(flow)];
    for (index, key) in keys.into_iter().enumerate() {
        let now = std::time::UNIX_EPOCH + Duration::from_millis(10 + index as u64);
        events.push(library::Event::Probe(library::ProbeEvidence {
            sequence: index as u64,
            flow_id: 1,
            sweep: 1,
            hop_limit: key.hop_limit,
            sent_at: now,
            replies_seen: 1,
            ambiguous: false,
            incomplete: false,
            replies: vec![library::Reply {
                responder: key.responder,
                kind: if index == 0 {
                    ResponseKind::Intermediate
                } else {
                    ResponseKind::DestinationReached
                },
                latency: Duration::from_millis(2),
                frame: Frame::new(
                    Some(now + Duration::from_millis(2)),
                    LinkType::RAW,
                    vec![0xde, 0xad, 0xbe, 0xef],
                )
                .unwrap(),
            }],
        }));
        events.push(library::Event::Topology(library::TopologyUpdate {
            nodes: vec![nodes[index].clone()],
            edges: if index == 0 {
                vec![]
            } else {
                vec![edge.clone()]
            },
            changes: vec![],
        }));
    }
    events.push(library::Event::FlowComplete(completion));
    let mut collector = library::Collector::default();
    let mut streamed = Vec::new();
    for event in events {
        collector.publish(event.clone()).unwrap();
        let wire = Published::<Event>::try_from(event).unwrap();
        streamed.push((
            wire.result.event_name(),
            serde_json::to_value(wire.result).unwrap(),
        ));
    }
    let terminal = Published::<Event>::from(report.clone());
    assert_eq!(terminal.result.event_name(), "complete");
    let terminal = serde_json::to_value(terminal.result).unwrap();
    let aggregate = Published::<Report>::try_from(collector.finish(report).unwrap()).unwrap();
    let aggregate = serde_json::to_value(aggregate.result).unwrap();
    for (event, field) in [
        ("flow", "flows"),
        ("probe", "probes"),
        ("flow_complete", "completions"),
    ] {
        let item = match event {
            "flow" => "flow",
            "probe" => "probe",
            _ => "completion",
        };
        let values: Vec<_> = streamed
            .iter()
            .filter(|(kind, _)| *kind == event)
            .map(|(_, value)| value[item].clone())
            .collect();
        assert_eq!(Value::Array(values), aggregate[field]);
    }
    let mut nodes = std::collections::BTreeMap::new();
    let mut edges = std::collections::BTreeMap::<String, Value>::new();
    for (_, update) in streamed.iter().filter(|(kind, _)| *kind == "topology") {
        for node in update["topology"]["nodes"].as_array().unwrap() {
            nodes.insert(
                format!("{}:{}", node["hop_limit"], node["responder"]),
                node.clone(),
            );
        }
        for edge in update["topology"]["edges"].as_array().unwrap() {
            let key = format!("{}:{}", edge["from"], edge["to"]);
            if let Some(previous) = edges.get_mut(&key) {
                previous["evidence"]
                    .as_array_mut()
                    .unwrap()
                    .extend(edge["evidence"].as_array().unwrap().iter().cloned());
            } else {
                edges.insert(key, edge.clone());
            }
        }
    }
    assert_eq!(
        json!(nodes.into_values().collect::<Vec<_>>()),
        aggregate["topology"]["nodes"]
    );
    assert_eq!(
        json!(edges.into_values().collect::<Vec<_>>()),
        aggregate["topology"]["edges"]
    );
    assert_eq!(aggregate["strategy"], "udp");
    assert_eq!(
        aggregate["completions"][0]["completion"],
        "destination_reached"
    );
    assert_eq!(aggregate["probes"][0]["replies"][0]["kind"], "intermediate");
    assert_eq!(terminal["summary"], aggregate["summary"]);
    assert_eq!(terminal["flow_summaries"], aggregate["flow_summaries"]);
    assert_eq!(
        aggregate["probes"][0]["replies"][0]["frame"]["bytes_hex"],
        "deadbeef"
    );
    assert_eq!(
        aggregate["probes"][0]["sent_at"],
        json!({"unix_seconds":0,"nanoseconds":10000000})
    );
    assert!(terminal.get("topology").is_none());
    assert!(terminal.get("probes").is_none());
}
