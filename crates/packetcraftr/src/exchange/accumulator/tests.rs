// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Accumulator;
use packetcraftr_netio::capture::ObservationQuality;

#[test]
fn every_matched_reply_refusal_qualifies_missing_observations() {
    for limit in [
        "exchange.response_limit",
        "exchange.capture_frame_limit",
        "exchange.capture_byte_limit",
    ] {
        for source in [
            ObservationQuality::Unknown,
            ObservationQuality::NoReportedLoss,
        ] {
            let mut captured = Accumulator::new(2);
            captured.record_response(0);
            captured.refuse_reply(1, limit);
            assert!(
                captured.unanswered(2).is_empty(),
                "a known refused reply is not ordinary unanswered evidence"
            );
            assert_eq!(captured.first_refused_reply(2), Some((1, limit)));
            assert_eq!(
                captured.observation_quality(source),
                ObservationQuality::Incomplete
            );
            // A later positive reply can settle that request, while acquisition
            // still reports the local refusal. Positive evidence remains usable.
            captured.record_response(1);
            assert_eq!(captured.first_refused_reply(2), None);
            assert_eq!(
                captured.observation_quality(source),
                ObservationQuality::Incomplete
            );
        }
    }
}

#[test]
fn clean_local_retention_does_not_promote_unknown_or_missing_ingress() {
    let mut captured = Accumulator::new(1);
    assert_eq!(
        captured.observation_quality(ObservationQuality::Unknown),
        ObservationQuality::Unknown
    );
    assert_eq!(
        captured.observation_quality(ObservationQuality::NoReportedLoss),
        ObservationQuality::NoReportedLoss
    );
    captured.ingress_unknown = true;
    assert_eq!(
        captured.observation_quality(ObservationQuality::NoReportedLoss),
        ObservationQuality::Unknown
    );
}
