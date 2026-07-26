// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "native-route")]
#[test]
fn native_plan_and_routes_are_passive_typed_workflows() {
    let plan = super::support::binary()
        .args([
            "--output",
            "json",
            "plan",
            "--packet",
            "ipv4(dst=127.0.0.1)/udp(dport=9)",
            "--link-mode",
            "layer3",
        ])
        .output()
        .unwrap();
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(plan["result"]["route"]["mode"], "layer3");
    assert!(
        plan["result"]["route"]["route"]["mtu"]
            .as_u64()
            .is_some_and(|mtu| mtu > 0)
    );

    let routes = super::support::binary()
        .args(["--output", "json", "routes"])
        .output()
        .unwrap();
    assert!(
        routes.status.success(),
        "{}",
        String::from_utf8_lossy(&routes.stderr)
    );
    let routes: serde_json::Value = serde_json::from_slice(&routes.stdout).unwrap();
    assert!(!routes["result"]["routes"].as_array().unwrap().is_empty());
}

#[cfg(all(windows, feature = "native-route"))]
#[test]
fn native_windows_interfaces_uses_ip_helper() {
    let output = super::support::binary()
        .args(["--output", "json", "interfaces"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "success");
    assert_eq!(value["command"], "interfaces");
    let interfaces = value["result"]["interfaces"].as_array().unwrap();
    assert!(!interfaces.is_empty());
    assert!(interfaces.iter().all(|interface| {
        interface["index"].as_u64().is_some_and(|index| index != 0)
            && interface["mtu"].as_u64().is_some_and(|mtu| mtu != 0)
    }));
}
