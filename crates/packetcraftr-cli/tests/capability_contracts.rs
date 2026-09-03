// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Exit code 4 and the fail-closed native stubs: the commands that need a
//! native capability report `capability.*` and exit 4 when the capability is
//! compiled out, and enumerate the loopback interface when it is compiled in.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod support;

use support::{parse_json, run};

/// Every failed process here must exit 4 with a `capability.*` code in both
/// renderings; text goes to stderr with nothing on stdout, JSON goes to stdout.
#[cfg(not(all(
    feature = "native-interfaces",
    any(feature = "native-layer2", feature = "native-layer3")
)))]
fn assert_capability_failure(arguments: &[&str]) {
    let text = run(arguments);
    assert_eq!(text.status.code(), Some(4), "{arguments:?}: {text:?}");
    assert!(text.stdout.is_empty(), "text errors leave stdout empty");
    let stderr = String::from_utf8_lossy(&text.stderr);
    assert!(
        stderr.starts_with("error[capability."),
        "{arguments:?} stderr: {stderr}"
    );

    let mut json_arguments = vec!["--output", "json"];
    json_arguments.extend_from_slice(arguments);
    let json = run(&json_arguments);
    assert_eq!(json.status.code(), Some(4), "{json_arguments:?}: {json:?}");
    let value = parse_json(&json);
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["kind"], "capability");
    let code = value["error"]["code"]
        .as_str()
        .expect("error code is a string");
    assert!(code.starts_with("capability."), "{code}");
}

#[cfg(not(feature = "native-interfaces"))]
#[test]
fn interfaces_and_routes_fail_closed_without_native_interfaces() {
    assert_capability_failure(&["interfaces"]);
    assert_capability_failure(&["routes"]);
}

#[cfg(not(any(feature = "native-layer2", feature = "native-layer3")))]
#[test]
fn send_fails_closed_without_a_native_transmit_backend() {
    assert_capability_failure(&[
        "send",
        "--packet",
        "raw(text=hi)",
        "--destination",
        "127.0.0.1",
    ]);
}

#[cfg(feature = "native-interfaces")]
#[test]
fn interfaces_enumerates_the_loopback_interface() {
    let text = run(&["interfaces"]);
    assert!(text.status.success(), "{text:?}");
    assert!(String::from_utf8_lossy(&text.stdout).contains("127.0.0.1"));

    let json = run(&["--output", "json", "interfaces"]);
    assert!(json.status.success(), "{json:?}");
    let value = parse_json(&json);
    assert_eq!(value["command"], "interfaces");
    let loopback = value["result"]["interfaces"]
        .as_array()
        .expect("interfaces is an array")
        .iter()
        .find(|interface| interface["flags"]["loopback"] == true)
        .expect("a loopback interface is listed");
    assert!(
        loopback["addresses"]
            .as_array()
            .expect("addresses is an array")
            .iter()
            .any(|address| address.as_str().is_some_and(|a| a.starts_with("127.")))
    );
}

#[cfg(feature = "native-route")]
#[test]
fn routes_reports_every_enumerated_interface_once() {
    let json = run(&["--output", "json", "routes"]);
    assert!(json.status.success(), "{json:?}");
    let value = parse_json(&json);
    assert_eq!(value["command"], "routes");
    let mut names = value["result"]["routes"]
        .as_array()
        .expect("routes is an array")
        .iter()
        .map(|route| {
            route["interface"]["name"]
                .as_str()
                .expect("interface name is a string")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert!(!names.is_empty(), "at least the loopback interface routes");
    let listed = names.len();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), listed, "each interface appears once");
}
