// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded diagnostic and capture-evidence retention for client operations.

use packetcraftr_packet::diagnostic::Diagnostic;
use packetcraftr_packet::diagnostic::push_diagnostic_once;

pub(super) fn reserve_capture_evidence(
    retained_frames: &mut usize,
    retained_bytes: &mut usize,
    additional: usize,
    frame_limit: usize,
    byte_limit: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    let Some(frame_total) = retained_frames.checked_add(1) else {
        push_diagnostic_once(
            diagnostics,
            Diagnostic::warning(
                "exchange.capture_frame_limit",
                "retained capture frame accounting overflowed; frame was not retained",
            ),
        );
        return false;
    };
    if frame_total > frame_limit {
        push_diagnostic_once(
            diagnostics,
            Diagnostic::warning(
                "exchange.capture_frame_limit",
                format!(
                    "aggregate retained capture frame limit {frame_limit} reached; later frames were not retained"
                ),
            ),
        );
        return false;
    }
    let Some(byte_total) = retained_bytes.checked_add(additional) else {
        push_diagnostic_once(
            diagnostics,
            Diagnostic::warning(
                "exchange.capture_byte_limit",
                "retained capture byte accounting overflowed; frame was not retained",
            ),
        );
        return false;
    };
    if byte_total > byte_limit {
        push_diagnostic_once(
            diagnostics,
            Diagnostic::warning(
                "exchange.capture_byte_limit",
                format!(
                    "retained capture byte limit {byte_limit} reached; later frames were not retained"
                ),
            ),
        );
        return false;
    }
    *retained_frames = frame_total;
    *retained_bytes = byte_total;
    true
}
