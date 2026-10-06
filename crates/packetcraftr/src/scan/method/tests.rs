// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_netio::{NativeCapability, Unsupported};

use super::{Capabilities, Method, Requested, select};
use crate::probe::ProbeEndpoint;
use crate::scan::Error;

const TCP: &[ProbeEndpoint] = &[ProbeEndpoint::Tcp { port: 443 }];
const MIXED: &[ProbeEndpoint] = &[
    ProbeEndpoint::Tcp { port: 53 },
    ProbeEndpoint::Udp { port: 53 },
];

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
            let selected = select(Requested::Raw, endpoints, capabilities(raw, true)).unwrap();
            assert_eq!((selected.method, selected.reason), (Method::Raw, None));
        }
    }
}

#[test]
fn explicit_connect_requires_tcp_and_the_kernel_route() {
    assert!(matches!(
        select(Requested::Connect, MIXED, capabilities(true, false)),
        Err(Error::MethodTransport {
            transport: "udp",
            ..
        })
    ));
    assert!(matches!(
        select(Requested::Connect, TCP, capabilities(true, true)),
        Err(Error::UnsupportedTcpRoute)
    ));
    let selected = select(Requested::Connect, TCP, capabilities(false, false)).unwrap();
    assert_eq!((selected.method, selected.reason), (Method::Connect, None));
}

#[test]
fn automatic_selection_prefers_raw_and_publishes_its_reason() {
    let raw = select(Requested::Automatic, MIXED, capabilities(true, false)).unwrap();
    assert_eq!(
        (raw.requested, raw.method),
        (Requested::Automatic, Method::Raw)
    );
    assert!(raw.reason.is_some());

    let connect = select(Requested::Automatic, TCP, capabilities(false, false)).unwrap();
    assert_eq!(connect.method, Method::Connect);
    assert!(connect.reason.unwrap().contains("not built"));

    // UDP or a pinned packet route leaves no ordinary-connection fallback,
    // so the selection stays raw and says what it lacks.
    for (endpoints, packet_route, need) in [
        (MIXED, false, "only the raw method can probe udp endpoints"),
        (
            TCP,
            true,
            "only the raw method can use the requested packet route",
        ),
    ] {
        let selected = select(
            Requested::Automatic,
            endpoints,
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
