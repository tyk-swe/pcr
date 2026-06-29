// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;

use serde_json::json;

use super::control::emission_accounting;
use super::error::{PlannerError, Result};
use super::types::{NetworkTarget, TransmissionPlan};

pub(crate) fn emit_metrics_snapshot(plan: &TransmissionPlan) -> Result<()> {
    let Some(path) = plan.logging.metrics_json.as_ref() else {
        return Ok(());
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| PlannerError::MetricsDirectory {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }

    let frames_per_iteration = plan.frames.len();
    let frame_sizes: Vec<usize> = plan.frames.iter().map(|frame| frame.len()).collect();
    let bytes_per_iteration: usize = frame_sizes.iter().sum();
    let largest_frame = plan.summary.largest_frame_len;

    let accounting = emission_accounting(
        &plan.transmit,
        plan.policy,
        u64::try_from(frames_per_iteration).unwrap_or(u64::MAX),
    )?;
    let mode = if let Some(attempts) = accounting.attempts {
        json!({
            "type": "finite",
            "iterations": attempts,
            "attempts": attempts,
            "units_per_attempt": accounting.units_per_attempt,
            "total_emitted_units": accounting.total_emitted_units,
        })
    } else {
        json!({
            "type": "infinite",
            "attempts": null,
            "units_per_attempt": accounting.units_per_attempt,
            "total_emitted_units": null,
        })
    };

    let interval_ms = plan.transmit.interval.map(|duration| duration.as_millis());
    let link = plan.link_type.as_str();
    let destination = match &plan.destination {
        NetworkTarget::Ipv4(addr) => addr.to_string(),
        NetworkTarget::Ipv6(addr) => addr.to_string(),
    };

    let snapshot = json!({
        "transport": plan.summary.transport,
        "link_type": link,
        "target": {
            "address": destination,
            "interface": plan.interface.name,
        },
        "frames": {
            "per_iteration": frames_per_iteration,
            "sizes": frame_sizes,
            "largest": largest_frame,
            "bytes_per_iteration": bytes_per_iteration,
            "payload_bytes": plan.summary.payload_len,
        },
        "transmit": {
            "count": plan.transmit.count,
            "flood": plan.transmit.flood,
            "loop": plan.transmit.loop_send,
            "force_layer3": plan.transmit.force_layer3,
            "auto_layer3": plan.transmit.auto_layer3,
            "layer3_active": plan.transmit.is_layer3(),
            "interval_ms": interval_ms,
        },
        "mode": mode,
    });

    let encoded =
        serde_json::to_string_pretty(&snapshot).map_err(PlannerError::MetricsSerialize)?;
    fs::write(path, encoded).map_err(|source| PlannerError::MetricsWrite {
        path: path.to_path_buf(),
        source,
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::spec::{LoggingSpec, TransmissionSpec};
    use crate::network::sender::types::{
        DestinationSelectionReason, InterfaceSelectionReason, LinkType, PlanningMode,
        SelectionMetadata, SourceSelectionReason, TransmissionSummary,
    };
    use pnet::datalink::NetworkInterface;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn create_test_interface() -> NetworkInterface {
        NetworkInterface {
            name: String::from("test0"),
            description: String::new(),
            index: 1,
            mac: None,
            ips: vec![],
            flags: 0,
        }
    }

    fn create_minimal_plan() -> TransmissionPlan {
        TransmissionPlan {
            frames: vec![vec![0x01, 0x02, 0x03], vec![0x04, 0x05]],
            link_type: LinkType::Ethernet,
            transmit: TransmissionSpec::default(),
            destination: NetworkTarget::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            interface: create_test_interface(),
            selection: SelectionMetadata {
                selected_interface: "test0".to_string(),
                interface_reason: InterfaceSelectionReason::ExplicitInterface,
                source_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                source_reason: SourceSelectionReason::InterfaceAddress,
                destination_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                destination_reason: DestinationSelectionReason::TargetLiteral,
            },
            protocol: IpNextHeaderProtocols::Tcp,
            summary: TransmissionSummary {
                payload_len: 100,
                largest_frame_len: 3,
                frame_count: 2,
                transport: "tcp",
            },
            logging: LoggingSpec::default(),
            mode: PlanningMode::Live,
            policy: crate::network::sender::TransmissionPolicy::default(),
        }
    }

    fn temp_metrics_path(filename: &str) -> (TempDir, PathBuf) {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let metrics_path = temp_dir.path().join(filename);
        (temp_dir, metrics_path)
    }

    #[test]
    fn emit_metrics_returns_ok_when_no_metrics_json_path() {
        let plan = create_minimal_plan();
        let result = emit_metrics_snapshot(&plan);
        assert!(result.is_ok());
    }

    #[test]
    fn emit_metrics_creates_parent_directories() {
        let (temp_dir, _metrics_path) = temp_metrics_path("unused.json");
        let nested_path = temp_dir.path().join("subdir").join("metrics.json");

        let mut plan = create_minimal_plan();
        plan.logging.metrics_json = Some(nested_path.clone());

        let result = emit_metrics_snapshot(&plan);
        assert!(result.is_ok());
        assert!(nested_path.exists());
    }

    #[test]
    fn emit_metrics_writes_emission_accounting() {
        let (_temp_dir, metrics_path) = temp_metrics_path("metrics_accounting.json");

        let mut plan = create_minimal_plan();
        plan.transmit.count = Some(3);
        plan.logging.metrics_json = Some(metrics_path.clone());

        emit_metrics_snapshot(&plan).expect("metrics snapshot");

        let content = std::fs::read_to_string(&metrics_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(parsed["mode"]["type"], "finite");
        assert_eq!(parsed["mode"]["attempts"], 3);
        assert_eq!(parsed["mode"]["units_per_attempt"], 2);
        assert_eq!(parsed["mode"]["total_emitted_units"], 6);
    }

    #[test]
    fn emit_metrics_handles_empty_frames() {
        let (_temp_dir, metrics_path) = temp_metrics_path("metrics_empty.json");

        let mut plan = create_minimal_plan();
        plan.frames = vec![];
        plan.summary.frame_count = 0;
        plan.logging.metrics_json = Some(metrics_path.clone());

        let result = emit_metrics_snapshot(&plan);
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&metrics_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(parsed["frames"]["per_iteration"], 0);
        assert_eq!(parsed["frames"]["bytes_per_iteration"], 0);
    }

    #[test]
    fn emit_metrics_returns_error_for_invalid_parent_directory() {
        let mut plan = create_minimal_plan();
        let (temp_dir, _metrics_path) = temp_metrics_path("unused.json");
        let invalid_parent = temp_dir.path().join("not_a_directory");
        std::fs::write(&invalid_parent, b"invalid parent").expect("write invalid parent");
        plan.logging.metrics_json = Some(invalid_parent.join("metrics.json"));

        let result = emit_metrics_snapshot(&plan);
        assert!(result.is_err());
    }
}
