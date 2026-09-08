// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_cli::output::stream::StreamRecord;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::{Stats, scan};
use packetcraftr_cli::output::scan as scan_output;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::frame::LinkType;

fn frame() -> Frame {
    Frame::new(UNIX_EPOCH, LinkType::IPV4, vec![0x45]).expect("bounded evidence frame")
}

fn endpoint(address: IpAddr, responded: bool) -> scan::Endpoint {
    let classification = if responded {
        packetcraftr::scan::Classification::Open
    } else {
        packetcraftr::scan::Classification::Timeout
    };
    scan::Endpoint {
        address,
        transport: packetcraftr::scan::Transport::Icmp,
        port: None,
        classification,
        probes: vec![scan::ProbeEvidence {
            sequence: 0,
            address,
            transport: packetcraftr::scan::Transport::Icmp,
            port: None,
            attempt: 1,
            status: if responded {
                packetcraftr::scan::ProbeStatus::Response
            } else {
                packetcraftr::scan::ProbeStatus::Timeout
            },
            classification,
            responder: responded.then_some(address),
            sent_at: UNIX_EPOCH,
            received_at: responded.then_some(UNIX_EPOCH + Duration::from_millis(5)),
            latency: responded.then_some(Duration::from_millis(5)),
            response: responded.then(frame),
            reason: if responded { "reply" } else { "timeout" }.to_owned(),
        }],
    }
}

#[test]
fn scan_output_preserves_endpoint_identity_and_port_absence() {
    let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let evidence_free = scan::Endpoint {
        address: ipv4,
        transport: packetcraftr::scan::Transport::Tcp,
        port: Some(443),
        classification: packetcraftr::scan::Classification::Unknown,
        probes: Vec::new(),
    };
    let port_zero = scan::Endpoint {
        port: Some(0),
        ..evidence_free.clone()
    };
    let (output, _, _) = scan_output::Report::try_from_scan(scan::Report {
        planned_duration: std::time::Duration::ZERO,
        target: "router.example".to_owned(),
        resolved_addresses: vec![ipv4, ipv6],
        endpoints: vec![
            endpoint(ipv4, true),
            endpoint(ipv6, false),
            evidence_free,
            port_zero,
        ],
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats: Stats::default(),
    })
    .expect("in-range evidence converts");

    assert_eq!(output.endpoints[0].address, ipv4);
    assert_eq!(output.endpoints[0].port, None);
    assert_eq!(
        output.endpoints[0].probes[0].protocol,
        scan_output::Protocol::Icmpv4
    );
    assert_eq!(output.endpoints[1].address, ipv6);
    assert_eq!(output.endpoints[1].port, None);
    assert_eq!(
        output.endpoints[1].probes[0].protocol,
        scan_output::Protocol::Icmpv6
    );
    assert_eq!(
        output.endpoints[0].classification,
        packetcraftr::scan::Classification::Open
    );
    assert_eq!(
        output.endpoints[1].classification,
        packetcraftr::scan::Classification::Timeout
    );
    assert_eq!(output.endpoints[2].address, ipv4);
    assert_eq!(output.endpoints[2].port, Some(443));
    assert!(output.endpoints[2].probes.is_empty());

    let json = serde_json::to_value(&output).expect("scan output serializes");
    assert!(json["endpoints"][0].get("port").is_none());
    assert_eq!(json["endpoints"][3]["port"], 0);
    let timeout = &json["endpoints"][1]["probes"][0];
    for absent in [
        "destination_port",
        "responder",
        "received_at",
        "latency",
        "frame",
    ] {
        assert!(timeout.get(absent).is_none(), "{absent} must be omitted");
    }

    let event = scan_output::Event::Probe {
        target: output.target,
        probe: output.endpoints[0].probes[0].clone(),
    };
    assert_eq!(event.event_name(), "probe");
    let event = serde_json::to_value(event).expect("probe payload serializes");
    assert_eq!(event["probe"]["destination"], ipv4.to_string());
    assert_eq!(event["probe"]["sequence"], 0);
    assert!(event["probe"].get("destination_port").is_none());
    assert!(event.get("resolved_address").is_none());

    let (undecoded, diagnostics) =
        scan_output::Event::try_from_scan(scan::Event::Undecoded { frame: frame() })
            .expect("undecoded event converts");
    assert!(diagnostics.is_empty());
    assert_eq!(undecoded.event_name(), "undecoded");
    let undecoded = serde_json::to_value(undecoded).expect("undecoded payload serializes");
    assert!(undecoded.get("probe_sequence").is_none());
    assert!(undecoded.get("address").is_none());
    assert!(undecoded.get("port").is_none());

    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/packetcraftr.output.v3.schema.json"
    ))
    .expect("output schema must be valid JSON");
    assert_eq!(
        schema["$defs"]["scanEndpoint"]["properties"]["port"]["minimum"],
        0
    );
}
