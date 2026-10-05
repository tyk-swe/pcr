// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr_core::{
    analysis::{
        self,
        export::{self, Selection},
    },
    error::{Classified, Kind},
};
#[test]
fn selected_limit_zero_above_ceiling_invalid() {
    for (max_selected_frames, reason) in [
        (0, analysis::Constraint::NonZero),
        (
            export::MAX_SELECTED_FRAMES + 1,
            analysis::Constraint::AtMost {
                maximum: export::MAX_SELECTED_FRAMES as u64,
            },
        ),
    ] {
        let error = Selection {
            datagram_frames: vec![2],
            max_selected_frames,
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert!(
            matches!(
                &error,
                export::Error::Analysis(analysis::Error::InvalidLimit {
                    field: "max_selected_frames",
                    value,
                    reason: actual,
                }) if (*value, *actual) == (max_selected_frames as u64, reason)
            ),
            "{error:?}"
        );
        let classification = error.classification();
        assert_eq!(classification.code, "cli.analysis_limit");
        assert_eq!(classification.kind, Kind::Usage);
    }
    for max_selected_frames in [1, export::MAX_SELECTED_FRAMES] {
        assert!(
            Selection {
                datagram_frames: vec![2],
                max_selected_frames,
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
    }
}
