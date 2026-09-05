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
#[cfg(not(any(feature = "native-layer2", feature = "native-layer3")))]
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

#[cfg(not(any(
    feature = "native-route",
    feature = "native-layer2",
    feature = "native-layer3"
)))]
#[test]
fn interfaces_and_routes_fail_closed_without_a_native_route_backend() {
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

#[cfg(any(
    feature = "native-route",
    feature = "native-layer2",
    feature = "native-layer3"
))]
#[test]
fn interfaces_enumerates_the_loopback_interface() {
    let text = run(&["interfaces"]);
    assert!(text.status.success(), "{text:?}");
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("127.0.0.1"), "{stdout}");
    // Every text row spells the fields the JSON document carries.
    for key in [
        "mtu=",
        "capability=",
        "link_type=",
        "mac=",
        "flags=",
        "description=",
    ] {
        assert!(stdout.contains(key), "missing {key:?} in:\n{stdout}");
    }

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

#[cfg(any(
    feature = "native-route",
    feature = "native-layer2",
    feature = "native-layer3"
))]
#[test]
fn interfaces_filters_to_one_interface_by_name_or_index() {
    let json = run(&["--output", "json", "interfaces"]);
    assert!(json.status.success(), "{json:?}");
    let loopback = parse_json(&json)["result"]["interfaces"]
        .as_array()
        .expect("interfaces is an array")
        .iter()
        .find(|interface| interface["flags"]["loopback"] == true)
        .expect("a loopback interface is listed")
        .clone();
    let name = loopback["name"].as_str().expect("name is a string");
    let index = loopback["index"].to_string();

    for selector in [name.to_owned(), index] {
        let filtered = run(&["interfaces", "--interface", &selector]);
        assert!(filtered.status.success(), "{selector}: {filtered:?}");
        let lines = String::from_utf8_lossy(&filtered.stdout)
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "{selector}: {lines:?}");
        assert!(lines[0].contains(name), "{selector}: {lines:?}");
    }

    let unknown = run(&[
        "interfaces",
        "--interface",
        "packetcraftr-no-such-interface",
    ]);
    assert_eq!(unknown.status.code(), Some(5), "{unknown:?}");
    assert!(unknown.stdout.is_empty(), "text errors leave stdout empty");
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("io.device"),
        "{unknown:?}"
    );
}

#[cfg(any(
    feature = "native-route",
    feature = "native-layer2",
    feature = "native-layer3"
))]
#[test]
fn routes_reports_each_eligible_interface_once() {
    let interfaces = run(&["--output", "json", "interfaces"]);
    assert!(interfaces.status.success(), "{interfaces:?}");
    let interfaces = parse_json(&interfaces);
    for all in [false, true] {
        let mut arguments = vec!["--output", "json", "routes"];
        if all {
            arguments.push("--all");
        }
        let json = run(&arguments);
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
            })
            .collect::<Vec<_>>();
        let mut expected = interfaces["result"]["interfaces"]
            .as_array()
            .expect("interfaces is an array")
            .iter()
            .filter(|interface| {
                (all || interface["flags"]["up"] == true)
                    && interface["mtu"].as_u64().is_some_and(|mtu| mtu > 0)
            })
            .map(|interface| {
                interface["name"]
                    .as_str()
                    .expect("interface name is a string")
            })
            .collect::<Vec<_>>();
        assert!(
            !expected.is_empty(),
            "at least the loopback interface routes"
        );
        names.sort();
        expected.sort();
        assert_eq!(names, expected, "each eligible interface appears once");
    }

    let text = run(&["routes", "--all"]);
    assert!(text.status.success(), "{text:?}");
    assert!(
        String::from_utf8_lossy(&text.stdout).contains("capability="),
        "{text:?}"
    );
}
