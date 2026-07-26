// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::capture::{Format as CaptureFormat, Reader};

use super::support::{binary, write_capture};

#[cfg(all(feature = "native-interfaces", unix))]
#[test]
fn interfaces_command_succeeds_end_to_end_on_supported_unix_profiles() {
    let output = binary()
        .args(["--output", "json", "interfaces"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "packetcraftr.output/v1");
    assert_eq!(value["command"], "interfaces");
    assert_eq!(value["status"], "success");
    assert!(value["result"]["interfaces"].is_array());
}

#[test]
fn empty_replay_supports_every_output_without_live_side_effects() {
    let path = write_capture(&[], false);
    for format in ["text", "json", "ndjson", "pcap", "pcapng"] {
        let output = binary()
            .args([
                "--output",
                format,
                "replay",
                path.to_str().unwrap(),
                "--interface",
                "definitely-missing-interface",
                "--timing",
                "immediate",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "{format}");
        match format {
            "text" => assert_eq!(
                std::str::from_utf8(&output.stdout).unwrap(),
                "replayed 0 frame(s), 0 byte(s), scheduled delay 0ns\n"
            ),
            "json" | "ndjson" => {
                let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(value["command"], "replay");
                assert_eq!(value["result"]["frames_attempted"], 0);
                assert_eq!(value["result"]["frames_completed"], 0);
                assert_eq!(value["result"]["bytes_completed"], 0);
                assert_eq!(
                    value["result"]["requested_interface"]["name"],
                    "definitely-missing-interface"
                );
                assert_eq!(value["result"]["frames"], serde_json::json!([]));
                if format == "ndjson" {
                    assert_eq!(value["sequence"], 0);
                }
            }
            "pcap" | "pcapng" => {
                let mut reader = Reader::new(std::io::Cursor::new(output.stdout)).unwrap();
                assert_eq!(
                    reader.format(),
                    if format == "pcap" {
                        CaptureFormat::Pcap
                    } else {
                        CaptureFormat::PcapNg
                    }
                );
                assert!(reader.next_frame().unwrap().is_none(), "{format}");
            }
            _ => unreachable!(),
        }
    }
    std::fs::remove_file(&path).unwrap();
}

#[cfg(all(windows, feature = "native-interfaces", not(feature = "native-route")))]
#[test]
fn default_windows_interfaces_uses_ip_helper() {
    let output = binary()
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

#[test]
fn interface_only_capture_requires_an_interface_and_rejects_route_arguments() {
    // A recipe-free capture observes one interface, so every argument that
    // configures a route lookup is refused rather than quietly ignored.
    for (arguments, expected) in [
        (
            vec!["capture"],
            "capture requires --interface when no --packet, --packet-file, or stdin recipe is supplied",
        ),
        (
            vec![
                "capture",
                "--interface",
                "lab0",
                "--destination",
                "192.0.2.1",
            ],
            "--destination configures a route lookup that interface-only capture does not perform",
        ),
        (
            vec!["capture", "--interface", "lab0", "--source", "192.0.2.9"],
            "--source configures a route lookup that interface-only capture does not perform",
        ),
        (
            vec!["capture", "--interface", "lab0", "--link-mode", "layer3"],
            "interface-only capture observes the link, so --link-mode layer3 cannot be honored",
        ),
    ] {
        let output = binary().args(&arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn interface_only_capture_rejects_an_unknown_interface_before_arming() {
    let output = binary()
        .args([
            "capture",
            "--interface",
            "definitely-not-an-interface",
            "--timeout-ms",
            "1",
        ])
        .output()
        .unwrap();

    // Without the native interface capability the failure is a capability
    // error; with it, the selector simply matches nothing. Either way nothing
    // is armed and the exit code is not success.
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn live_decode_rejects_aggregate_json_before_arming_a_capture() {
    let output = binary()
        .args([
            "--output",
            "json",
            "decode",
            "--interface",
            "lab0",
            "--timeout-ms",
            "1",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["command"], "decode");
    assert_eq!(value["status"], "error");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("streams frames as they arrive"),
        "{value}"
    );
}

#[test]
fn decode_takes_exactly_one_of_a_capture_file_or_an_interface() {
    let neither = binary().arg("decode").output().unwrap();
    assert_eq!(neither.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&neither.stderr).contains("required arguments were not provided"),
        "{}",
        String::from_utf8_lossy(&neither.stderr)
    );

    let both = binary()
        .args(["decode", "capture.pcapng", "--interface", "lab0"])
        .output()
        .unwrap();
    assert_eq!(both.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&both.stderr).contains("cannot be used with"),
        "{}",
        String::from_utf8_lossy(&both.stderr)
    );
}
