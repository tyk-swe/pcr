// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;

use serde_json::json;

use super::control::emission_accounting;
use super::error::{PlannerError, Result};
use super::types::{NetworkTarget, NetworkTransmissionPlan};

pub(crate) fn emit_metrics_snapshot(plan: &NetworkTransmissionPlan) -> Result<()> {
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
    let frame_sizes: Vec<usize> = plan.frames.iter().map(Vec::len).collect();
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
