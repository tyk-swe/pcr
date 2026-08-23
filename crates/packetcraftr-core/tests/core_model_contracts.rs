// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error as _;
use std::fmt;
use std::time::{Duration, SystemTime};

use packetcraftr_core::{
    budget::Deadline,
    build, decode, document,
    error::{BoundaryError, Classification, Classified, Kind},
    expression, filter,
    frame::{Direction, Frame, LinkType},
};

#[derive(Debug)]
struct ClassifiedFailure;

impl fmt::Display for ClassifiedFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("classified failure")
    }
}

impl std::error::Error for ClassifiedFailure {}

impl Classified for ClassifiedFailure {
    fn classification(&self) -> Classification {
        Classification::new("internal.test_failure", Some("repair the fixture"))
    }

    fn causes(&self) -> Vec<String> {
        vec!["wire cause".to_owned(), "schema cause".to_owned()]
    }
}

#[test]
fn deadline_accepts_bounded_phases_and_preserves_limit_on_failure() {
    let mut deadline = Deadline::new(Duration::from_secs(60));

    assert!(deadline.check().is_ok(), "fresh deadline must be available");
    assert!(
        deadline.check_additional(Duration::from_secs(1)).is_ok(),
        "bounded prospective work must fit"
    );
    assert!(
        deadline.start_accounting(Duration::from_secs(1)).is_ok(),
        "bounded phase must start"
    );
    assert!(
        deadline.account(Duration::from_secs(1)).is_ok(),
        "bounded phase must commit"
    );

    let error = deadline
        .check_additional(Duration::from_secs(61))
        .expect_err("ordinary prospective work above the limit must fail");
    assert!(error.actual > error.limit);
    assert_eq!(error.limit, Duration::from_secs(60));

    let error = deadline
        .check_additional(Duration::MAX)
        .expect_err("duration addition overflow must fail closed");
    assert_eq!(error.actual, Duration::MAX);
    assert_eq!(error.limit, Duration::from_secs(60));

    let error = deadline
        .account(Duration::from_secs(61))
        .expect_err("committed accounting above the limit must fail");
    assert!(error.actual > error.limit);
}

#[test]
fn rejected_prospective_phase_does_not_spend_the_deadline() {
    let mut deadline = Deadline::new(Duration::from_secs(30));

    assert!(deadline.start_accounting(Duration::from_secs(31)).is_err());
    assert!(
        deadline.check_additional(Duration::from_secs(1)).is_ok(),
        "a rejected phase must not be committed"
    );
}

#[test]
fn frame_new_sets_exact_lengths_and_exposes_metadata() {
    let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(7);
    let mut frame = Frame::new(timestamp, LinkType::RAW, vec![1_u8, 2, 3])
        .expect("small frame must fit capture lengths");
    frame.interface = Some(9);
    frame.direction = Some(Direction::Outbound);

    assert_eq!(frame.timestamp, Some(timestamp));
    assert_eq!(frame.link_type, LinkType::RAW);
    assert_eq!(frame.captured_length(), 3);
    assert_eq!(frame.original_length(), 3);
    assert_eq!(frame.bytes().as_ref(), [1, 2, 3]);
    assert_eq!(frame.interface, Some(9));
    assert_eq!(frame.direction, Some(Direction::Outbound));

    let serialized = serde_json::to_value(&frame).expect("frame must serialize");
    let round_trip: Frame =
        serde_json::from_value(serialized).expect("valid serialized frame must deserialize");
    assert_eq!(round_trip, frame);
}

#[test]
fn frame_accepts_truncated_capture_when_original_is_larger() {
    let frame = Frame::try_with_lengths(
        SystemTime::UNIX_EPOCH,
        LinkType::LINUX_SLL2,
        2,
        100,
        vec![0xaa_u8, 0xbb],
    )
    .expect("capture records may retain only a prefix of the original frame");

    assert_eq!(frame.captured_length(), 2);
    assert_eq!(frame.original_length(), 100);
    assert_eq!(frame.bytes().as_ref(), [0xaa, 0xbb]);
}

#[test]
fn frame_lengths_fail_closed_during_construction_and_deserialization() {
    let cases = [
        (
            2,
            2,
            vec![0_u8],
            packetcraftr_core::frame::Error::CapturedLengthMismatch {
                declared: 2,
                actual: 1,
            },
        ),
        (
            2,
            1,
            vec![0_u8, 1],
            packetcraftr_core::frame::Error::OriginalLengthTooSmall {
                captured: 2,
                original: 1,
            },
        ),
    ];

    for (captured, original, bytes, expected) in cases {
        let error = Frame::try_with_lengths(
            SystemTime::UNIX_EPOCH,
            LinkType::ETHERNET,
            captured,
            original,
            bytes,
        )
        .expect_err("invalid capture lengths must be rejected");
        assert_eq!(error, expected);
    }

    let invalid = serde_json::json!({
        "captured_length": 2,
        "original_length": 2,
        "link_type": LinkType::ETHERNET.0,
        "bytes": [0]
    });
    let error = serde_json::from_value::<Frame>(invalid)
        .expect_err("deserialization must revalidate capture lengths");
    assert!(error.to_string().contains("says 2 bytes but contains 1"));
}

#[test]
fn link_type_constants_retain_open_numeric_values() {
    assert_eq!(LinkType::NULL.0, 0);
    assert_eq!(LinkType::ETHERNET.0, 1);
    assert_eq!(LinkType::BSD_RAW.0, 12);
    assert_eq!(LinkType::RAW.0, 101);
    assert_eq!(LinkType::LOOP.0, 108);
    assert_eq!(LinkType::LINUX_SLL.0, 113);
    assert_eq!(LinkType::IPV4.0, 228);
    assert_eq!(LinkType::IPV6.0, 229);
    assert_eq!(LinkType::LINUX_SLL2.0, 276);
    assert!(LinkType(65_535) > LinkType::ETHERNET);
}

#[test]
fn erased_classified_error_retains_source_classification_and_causes() {
    let error = BoundaryError::from_error(ClassifiedFailure);

    assert_eq!(error.to_string(), "classified failure");
    assert_eq!(
        error.classification(),
        Classification::new("internal.test_failure", Some("repair the fixture"))
    );
    assert_eq!(error.causes(), ["wire cause", "schema cause"]);
    assert_eq!(
        error.source().map(ToString::to_string).as_deref(),
        Some("classified failure")
    );
}

#[test]
fn boundary_error_new_preserves_the_supplied_contract() {
    let classification = Classification::new("policy.test", Some("stop"));
    let error = BoundaryError::new("denied", classification, vec!["first".to_owned()]);

    assert_eq!(error.to_string(), "denied");
    assert_eq!(error.classification(), classification);
    assert_eq!(error.causes(), ["first"]);
}

#[test]
fn boundary_constructors_distinguish_validation_from_internal_failures() {
    let validation = BoundaryError::new(
        "bad request",
        Classification::new("cli.test", Some("change the request")),
        Vec::new(),
    );
    assert_eq!(validation.classification().kind, Kind::Cli);
    assert_eq!(validation.classification().code, "cli.test");
    assert_eq!(
        validation.classification().remediation,
        Some("change the request")
    );
    assert!(validation.source().is_none());

    let internal = BoundaryError::new(
        "broken executor",
        Classification::new("internal.test", Some("replace the executor")),
        Vec::new(),
    );
    assert_eq!(internal.classification().kind, Kind::Internal);
    assert_eq!(internal.classification().code, "internal.test");
}

#[test]
fn every_error_kind_has_a_stable_machine_name() {
    let cases = [
        (Kind::Cli, "cli"),
        (Kind::Packet, "packet"),
        (Kind::Capability, "capability"),
        (Kind::Io, "io"),
        (Kind::Policy, "policy"),
        (Kind::Internal, "internal"),
    ];

    for (kind, expected) in cases {
        assert_eq!(kind.as_str(), expected);
    }
}

#[test]
fn build_errors_have_stable_classifications() {
    let cases = [
        (build::Error::LengthOverflow, "packet.build_limit"),
        (build::Error::EmptyPacket, "packet.build"),
        (
            build::Error::MissingCodec {
                index: 0,
                protocol: packetcraftr_core::layer::Id::new("missing"),
            },
            "packet.unknown_protocol",
        ),
        (
            build::Error::InvalidCodecLayout {
                protocol: packetcraftr_core::layer::Id::new("fixture"),
            },
            "internal.codec_contract",
        ),
    ];

    for (error, expected_code) in cases {
        let classification = error.classification();
        assert_eq!(classification.code, expected_code);
        assert_eq!(Kind::from_code(expected_code), Some(classification.kind));
    }
}

#[test]
fn decode_errors_have_stable_classifications() {
    let cases = [
        (
            decode::Error::PacketSizeLimit {
                actual: 2,
                limit: 1,
            },
            "packet.decode_limit",
        ),
        (
            decode::Error::MissingRootCodec {
                protocol: packetcraftr_core::layer::Id::new("missing"),
            },
            "packet.decode",
        ),
        (
            decode::Error::InvalidCodecCursor {
                protocol: packetcraftr_core::layer::Id::new("fixture"),
            },
            "internal.codec_contract",
        ),
    ];

    for (error, expected_code) in cases {
        let classification = error.classification();
        assert_eq!(classification.code, expected_code);
        assert_eq!(Kind::from_code(expected_code), Some(classification.kind));
    }
}

#[test]
fn document_errors_have_stable_classifications() {
    let cases = [
        (
            document::Error::SizeLimit {
                actual: 2,
                limit: 1,
            },
            "cli.packet_document",
        ),
        (
            document::Error::Serialize {
                format: "json",
                message: "fixture".to_owned(),
            },
            "internal.document_serialize",
        ),
    ];

    for (error, expected_code) in cases {
        let classification = error.classification();
        assert_eq!(classification.code, expected_code);
        assert_eq!(Kind::from_code(expected_code), Some(classification.kind));
    }
}

#[test]
fn expression_errors_have_stable_classifications() {
    let cases = [(expression::Error::Empty, "cli.packet_expression")];

    for (error, expected_code) in cases {
        let classification = error.classification();
        assert_eq!(classification.code, expected_code);
        assert_eq!(Kind::from_code(expected_code), Some(classification.kind));
    }
}

#[test]
fn frame_errors_have_stable_classifications() {
    let cases = [(
        packetcraftr_core::frame::Error::CapturedLengthTooLarge { actual: 1 },
        "packet.frame_length",
    )];

    for (error, expected_code) in cases {
        let classification = error.classification();
        assert_eq!(classification.code, expected_code);
        assert_eq!(Kind::from_code(expected_code), Some(classification.kind));
    }
}

#[test]
fn filter_errors_have_stable_classifications() {
    let cases = [
        (
            filter::Error::UnknownField {
                offset: 0,
                path: "missing".to_owned(),
            },
            "cli.filter_field",
        ),
        (
            filter::Error::IncompatibleLiteral {
                offset: 0,
                path: "frame.len".to_owned(),
                kind: "unsigned",
                literal: "text".to_owned(),
            },
            "cli.filter_type",
        ),
        (
            filter::Error::UnsliceableField {
                offset: 0,
                path: "frame.len".to_owned(),
            },
            "cli.filter_slice",
        ),
        (
            filter::Error::SizeLimit {
                actual: 2,
                limit: 1,
            },
            "cli.filter_limit",
        ),
        (filter::Error::Empty, "cli.filter"),
        (
            filter::Error::TimestampUnavailable,
            "packet.timestamp_unavailable",
        ),
    ];

    for (error, expected_code) in cases {
        let classification = error.classification();
        assert_eq!(classification.code, expected_code);
        assert_eq!(Kind::from_code(expected_code), Some(classification.kind));
    }
}
