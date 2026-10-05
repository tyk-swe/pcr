// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_core::fuzz;

#[test]
fn fuzz_fails_retain_stable_boundary_class() {
    let cases = [
        (
            fuzz::Error::InvalidStrategies,
            "cli.fuzz_limit",
            Kind::Usage,
        ),
        (
            fuzz::Error::InvalidBasePacket {
                reason: fuzz::BaseFault::FieldCountOverflow,
            },
            "packet.fuzz_recipe",
            Kind::Packet,
        ),
        (
            fuzz::Error::NoCompatibleTargets,
            "packet.fuzz_target",
            Kind::Packet,
        ),
        (
            fuzz::Error::ByteLimit {
                actual: 11,
                limit: 10,
            },
            "policy.fuzz_resource_limit",
            Kind::Policy,
        ),
        (
            fuzz::Error::ValueNesting {
                limit: fuzz::MAX_VALUE_NESTING,
            },
            "policy.fuzz_resource_limit",
            Kind::Policy,
        ),
        (
            fuzz::Error::DurationLimit {
                actual: Duration::from_secs(11),
                limit: Duration::from_secs(10),
            },
            "policy.fuzz_resource_limit",
            Kind::Policy,
        ),
    ];

    for (error, code, kind) in cases {
        let classification = error.classification();
        assert_eq!(classification.code, code);
        assert_eq!(classification.kind, kind);
        assert!(classification.remediation.is_some());
        assert!(error.causes().is_empty());
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn campaign_limits_reject_ceilings_enforce() {
    for limits in [
        fuzz::Limits {
            max_total_bytes: fuzz::MAX_TOTAL_BYTES + 1,
            ..fuzz::Limits::default()
        },
        fuzz::Limits {
            max_packet_bytes: fuzz::MAX_PACKET_BYTES + 1,
            ..fuzz::Limits::default()
        },
    ] {
        assert!(matches!(
            limits.validate(),
            Err(fuzz::Error::InvalidLimit { .. })
        ));
    }
    assert!(fuzz::Limits::default().validate().is_ok());
    const {
        assert!(fuzz::MAX_VALUE_NESTING <= packetcraftr_core::document::MAX_DOCUMENT_NESTING);
    }
}
