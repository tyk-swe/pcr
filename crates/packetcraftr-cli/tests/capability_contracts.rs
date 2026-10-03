// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

#[cfg(not(any(
    feature = "native-route",
    feature = "native-layer2",
    feature = "native-layer3"
)))]
fn assert_capability_failure(arguments: &[&str]) {
    use common::{parse_json, run};

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
