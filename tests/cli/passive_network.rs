// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::capture::{Format as CaptureFormat, Reader};

use super::support::{binary, write_capture};

#[cfg(all(feature = "live", unix))]
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

#[cfg(all(windows, feature = "live", not(feature = "native-route")))]
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
