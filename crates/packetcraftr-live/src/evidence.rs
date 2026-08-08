// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded diagnostic and capture-evidence retention for client operations.

use packetcraftr_packet::diagnostic::{Diagnostic, push_diagnostic_once};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_commits_both_counters_only_when_every_bound_fits() {
        let mut frames = 1;
        let mut bytes = 10;
        let mut diagnostics = Vec::new();
        assert!(reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            5,
            2,
            15,
            &mut diagnostics,
        ));
        assert_eq!((frames, bytes), (2, 15));
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn frame_limit_and_overflow_leave_counters_untouched_and_deduplicate_diagnostics() {
        let mut frames = 1;
        let mut bytes = 3;
        let mut diagnostics = Vec::new();
        assert!(!reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            1,
            1,
            10,
            &mut diagnostics,
        ));
        assert!(!reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            1,
            1,
            10,
            &mut diagnostics,
        ));
        assert_eq!((frames, bytes), (1, 3));
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "exchange.capture_frame_limit");

        frames = usize::MAX;
        diagnostics.clear();
        assert!(!reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            1,
            usize::MAX,
            10,
            &mut diagnostics,
        ));
        assert_eq!(frames, usize::MAX);
        assert_eq!(bytes, 3);
        assert_eq!(diagnostics[0].code, "exchange.capture_frame_limit");
    }

    #[test]
    fn byte_limit_and_overflow_leave_counters_untouched() {
        let mut frames = 1;
        let mut bytes = 9;
        let mut diagnostics = Vec::new();
        assert!(!reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            2,
            10,
            10,
            &mut diagnostics,
        ));
        assert_eq!((frames, bytes), (1, 9));
        assert_eq!(diagnostics[0].code, "exchange.capture_byte_limit");

        bytes = usize::MAX;
        diagnostics.clear();
        assert!(!reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            1,
            10,
            usize::MAX,
            &mut diagnostics,
        ));
        assert_eq!((frames, bytes), (1, usize::MAX));
        assert_eq!(diagnostics[0].code, "exchange.capture_byte_limit");
    }
}
