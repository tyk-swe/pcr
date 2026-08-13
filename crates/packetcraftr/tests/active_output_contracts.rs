// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::core::frame::{Frame, LinkType};
use packetcraftr::output::scan as scan_output;
use packetcraftr::{Stats, scan};

fn frame() -> Frame {
    Frame::new(UNIX_EPOCH, LinkType::IPV4, vec![0x45]).expect("bounded evidence frame")
}

fn endpoint(address: IpAddr, responded: bool) -> scan::Endpoint {
    let classification = if responded {
        scan::Classification::Open
    } else {
        scan::Classification::Timeout
    };
    scan::Endpoint {
        address,
        transport: scan::Transport::Icmp,
        port: None,
        classification,
        evidence: vec![scan::ProbeEvidence {
            attempt: 1,
            status: if responded {
                scan::ProbeStatus::Response
            } else {
                scan::ProbeStatus::Timeout
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
        transport: scan::Transport::Tcp,
        port: Some(443),
        classification: scan::Classification::Unknown,
        evidence: Vec::new(),
    };
    let port_zero = scan::Endpoint {
        port: Some(0),
        ..evidence_free.clone()
    };
    let (output, _, _) = scan_output::Result::try_from_scan(scan::Result {
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
    assert_eq!(output.endpoints[0].evidence[0].protocol, "icmpv4");
    assert_eq!(output.endpoints[1].address, ipv6);
    assert_eq!(output.endpoints[1].port, None);
    assert_eq!(output.endpoints[1].evidence[0].protocol, "icmpv6");
    assert_eq!(
        output.endpoints[0].classification,
        scan_output::Classification::Open
    );
    assert_eq!(
        output.endpoints[1].classification,
        scan_output::Classification::Timeout
    );
    assert_eq!(output.endpoints[2].address, ipv4);
    assert_eq!(output.endpoints[2].port, Some(443));
    assert!(output.endpoints[2].evidence.is_empty());

    let json = serde_json::to_value(&output).expect("scan output serializes");
    assert!(json["endpoints"][0].get("port").is_none());
    assert_eq!(json["endpoints"][3]["port"], 0);
    let timeout = &json["endpoints"][1]["evidence"][0];
    for absent in [
        "destination_port",
        "responder",
        "received_at",
        "latency",
        "frame",
    ] {
        assert!(timeout.get(absent).is_none(), "{absent} must be omitted");
    }

    let event = serde_json::to_value(scan_output::Event::Endpoint {
        target: output.target,
        endpoint: output.endpoints[2].clone(),
    })
    .expect("endpoint event serializes without evidence");
    assert_eq!(event["event"], "endpoint");
    assert_eq!(event["endpoint"]["address"], ipv4.to_string());
    assert!(event.get("resolved_address").is_none());

    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/packetcraftr.output.v1.schema.json"
    ))
    .expect("output schema must be valid JSON");
    assert_eq!(
        schema["$defs"]["scanEndpoint"]["properties"]["port"]["minimum"],
        0
    );
}
