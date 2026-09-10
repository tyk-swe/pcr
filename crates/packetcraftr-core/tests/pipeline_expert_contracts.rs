// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::analysis::Error;
use packetcraftr_core::analysis::reassembly::tcp;
use packetcraftr_core::error::{BoundaryError, Classified, Kind};

#[test]
fn analysis_errors_keep_policy_packet_and_boundary_classifications_distinct() {
    let invalid = Error::InvalidLimit {
        field: "max_flows",
        value: 0,
        reason: "must be non-zero",
    };
    assert_eq!(invalid.classification().kind, Kind::Cli);
    let stream = Error::StreamLimit {
        number: 2,
        limit: 1,
    };
    assert_eq!(stream.classification().kind, Kind::Policy);
    let malformed = Error::Reassembly {
        number: 3,
        source: tcp::MalformedError::ConflictingFinalSequence {
            existing_offset: 1,
            new_offset: 2,
        }
        .into(),
    };
    assert_eq!(malformed.classification().kind, Kind::Packet);
    assert_eq!(malformed.causes().len(), 1);
    let bounded = Error::Reassembly {
        number: 3,
        source: tcp::ResourceError::FlowByteLimit { limit: 8 }.into(),
    };
    assert_eq!(bounded.classification().kind, Kind::Policy);
    let tcp_remediation = bounded
        .classification()
        .remediation
        .expect("TCP resource failures have remediation");
    assert!(tcp_remediation.contains("trim or pre-filter the capture"));
    // A TCP budget failure must point at the TCP budgets, not tell the
    // operator to inspect the flow instead of raising them.
    assert!(tcp_remediation.contains("--max-tcp-*"));
    let bounded_ip = Error::IpReassembly {
        number: 3,
        source: packetcraftr_core::analysis::reassembly::ip::ResourceError::AggregateMemoryLimit {
            limit: 8,
        }
        .into(),
    };
    let remediation = bounded_ip
        .classification()
        .remediation
        .expect("IP resource failures have remediation");
    assert!(remediation.contains("trim or pre-filter the capture"));
    assert!(remediation.contains("--max-ip-*"));
    // An engine invariant that broke is neither the operator's capture nor
    // their budget, so it must not be reported as either.
    let inconsistent = Error::IpReassembly {
        number: 4,
        source: packetcraftr_core::analysis::reassembly::ip::Error::Inconsistent {
            reason: "retained datagram family disagrees with its key",
        },
    };
    assert_eq!(inconsistent.classification().kind, Kind::Internal);
    assert_eq!(inconsistent.classification().code, "internal.ip_reassembly");
    let bounded_scope = Error::Scope {
        number: 3,
        source: packetcraftr_core::analysis::scope::Error::Limit { limit: 8 },
    };
    assert_eq!(bounded_scope.classification().kind, Kind::Policy);
    for source in [
        packetcraftr_core::analysis::scope::Error::Unknown { scope: 7 },
        packetcraftr_core::analysis::scope::Error::ReplayMismatch { scope: 7 },
    ] {
        let invariant = Error::Scope { number: 3, source };
        assert_eq!(invariant.classification().kind, Kind::Internal);
        assert_eq!(
            invariant.classification().code,
            "internal.scope_composition"
        );
    }
    let sink = Error::Sink {
        number: 4,
        source: BoundaryError::execution_validation("bad sink", "test.sink", "repair it"),
    };
    assert_eq!(sink.classification().code, "test.sink");
    assert_eq!(sink.causes(), Vec::<String>::new());
}
