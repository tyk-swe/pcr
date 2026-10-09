// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_netio::{NativeCapability, Unsupported};

use super::{Capabilities, Method, Requested, select};
use crate::probe::ProbeEndpoint;
use crate::scan::discovery::{self, Mode};
use crate::scan::{Error, Limits, Request};
use crate::target::{Family, Target};

const TCP: &[ProbeEndpoint] = &[ProbeEndpoint::Tcp { port: 443 }];
const MIXED: &[ProbeEndpoint] = &[
    ProbeEndpoint::Tcp { port: 53 },
    ProbeEndpoint::Udp { port: 53 },
];

fn request(endpoints: &[ProbeEndpoint]) -> Request {
    Request {
        max_in_flight: 1,
        targets: Target::Address("192.0.2.1".parse().unwrap()).into(),
        target_sources: Vec::new(),
        endpoints: endpoints.to_vec(),
        discovery: discovery::Options::default(),
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        attempts: 1,
        adaptive: None,
        timeout: std::time::Duration::from_millis(1),
        probes_per_second: None,
        limits: Limits::default(),
        route: crate::route::Options::default(),
        collection: crate::exchange::Collection::default(),
    }
}

fn discovering(probes: &[ProbeEndpoint], neighbor: bool) -> Request {
    Request {
        discovery: discovery::Options {
            mode: Mode::Before,
            probes: probes.to_vec(),
            neighbor,
            ..discovery::Options::default()
        },
        ..request(TCP)
    }
}

fn capabilities(raw: bool, packet_route: bool) -> Capabilities {
    Capabilities {
        raw: if raw {
            Ok(())
        } else {
            Err(Unsupported::new(NativeCapability::Capture, "not built"))
        },
        packet_route,
    }
}

#[test]
fn explicit_raw_is_never_replaced_by_a_connection() {
    // Without packet I/O the raw engine reports the capability error after
    // policy review; selection keeps the request as it was made.
    for raw in [false, true] {
        for endpoints in [TCP, MIXED] {
            let selected =
                select(Requested::Raw, &request(endpoints), capabilities(raw, true)).unwrap();
            assert_eq!((selected.method, selected.reason), (Method::Raw, None));
        }
    }
}

#[test]
fn explicit_connect_requires_tcp_and_the_kernel_route() {
    assert!(matches!(
        select(
            Requested::Connect,
            &request(MIXED),
            capabilities(true, false)
        ),
        Err(Error::MethodProbe { probe: "udp", .. })
    ));
    assert!(matches!(
        select(Requested::Connect, &request(TCP), capabilities(true, true)),
        Err(Error::UnsupportedTcpRoute)
    ));
    let selected = select(
        Requested::Connect,
        &request(TCP),
        capabilities(false, false),
    )
    .unwrap();
    assert_eq!((selected.method, selected.reason), (Method::Connect, None));
}

#[test]
fn automatic_selection_prefers_raw_and_publishes_its_reason() {
    let raw = select(
        Requested::Automatic,
        &request(MIXED),
        capabilities(true, false),
    )
    .unwrap();
    assert_eq!(
        (raw.requested, raw.method),
        (Requested::Automatic, Method::Raw)
    );
    assert!(raw.reason.is_some());

    let connect = select(
        Requested::Automatic,
        &request(TCP),
        capabilities(false, false),
    )
    .unwrap();
    assert_eq!(connect.method, Method::Connect);
    assert!(connect.reason.unwrap().contains("not built"));

    // UDP or a pinned packet route leaves no ordinary-connection fallback,
    // so the selection stays raw and says what it lacks.
    for (endpoints, packet_route, need) in [
        (MIXED, false, "only the raw method can send udp probes"),
        (
            TCP,
            true,
            "only the raw method can use the requested packet route",
        ),
    ] {
        let selected = select(
            Requested::Automatic,
            &request(endpoints),
            capabilities(false, packet_route),
        )
        .unwrap();
        assert_eq!(selected.method, Method::Raw);
        let reason = selected.reason.unwrap();
        assert!(
            reason.contains("not built") && reason.contains(need),
            "{reason}"
        );
    }
}

#[test]
fn discovery_probes_take_part_in_the_selection() {
    // Discovery probes the connection cannot send rule it out exactly as
    // scan endpoints do; neighbor discovery needs crafted frames.
    for (request, probe) in [
        (discovering(&[ProbeEndpoint::Icmp], false), "icmp"),
        (discovering(TCP, true), "neighbor"),
    ] {
        assert!(matches!(
            select(Requested::Connect, &request, capabilities(true, false)),
            Err(Error::MethodProbe { probe: actual, .. }) if actual == probe
        ));
        let selected = select(Requested::Automatic, &request, capabilities(false, false)).unwrap();
        assert_eq!(selected.method, Method::Raw);
        assert!(selected.reason.unwrap().contains(probe));
    }
    let tcp = discovering(&[ProbeEndpoint::Tcp { port: 80 }], false);
    let selected = select(Requested::Automatic, &tcp, capabilities(false, false)).unwrap();
    assert_eq!(selected.method, Method::Connect);
}
