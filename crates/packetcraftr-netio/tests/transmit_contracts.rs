// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use bytes::Bytes;
use packetcraftr_netio::{
    Error,
    link::{Capability, Mode},
    route::Decision,
    transmit::{Layer2Frame, Layer3Frame, Outbound, Report, Route, Submission},
};

fn route(decision: &Decision, mode: Mode) -> Route<'_> {
    Route {
        decision,
        mode,
        lookup_destination: Some(common::lookup_destination()),
    }
}

#[test]
fn typed_transmissions_enforce_mode_and_select_the_resolved_layer() {
    let bytes = Bytes::from_static(&[1, 2, 3]);
    let decision = common::decision(Capability::Layer2AndLayer3);
    let layer2_route = route(&decision, Mode::Layer2);
    let layer3_route = route(&decision, Mode::Layer3);
    let auto_route = route(&decision, Mode::Auto);

    assert!(matches!(
        Layer2Frame::try_new(&bytes, layer3_route),
        Err(Error::TransmissionModeMismatch {
            expected: Mode::Layer2,
            actual: Mode::Layer3
        })
    ));
    assert!(matches!(
        Layer3Frame::try_new(&bytes, layer2_route),
        Err(Error::TransmissionModeMismatch {
            expected: Mode::Layer3,
            actual: Mode::Layer2
        })
    ));
    assert!(matches!(
        Outbound::try_new(&bytes, auto_route),
        Err(Error::UnresolvedLinkMode)
    ));

    let layer2 = Outbound::try_new(&bytes, layer2_route).expect("Layer 2 frame");
    assert!(matches!(layer2, Outbound::Layer2(_)));
    assert_eq!(layer2.bytes(), &bytes);
    assert_eq!(layer2.route(), layer2_route);

    let layer3 = Outbound::try_new(&bytes, layer3_route).expect("Layer 3 packet");
    assert!(matches!(layer3, Outbound::Layer3(_)));
    assert_eq!(layer3.bytes(), &bytes);
    assert_eq!(layer3.route(), layer3_route);
}

#[test]
fn send_reports_validate_counts_bytes_and_provider_timing() {
    let expected = Bytes::from_static(&[1, 2, 3]);
    let submission = Submission::start();
    let started = submission.started();
    let report = submission.complete(expected.len(), expected.clone());

    assert_eq!(report.bytes_sent(), expected.len());
    assert_eq!(report.wire_bytes(), &expected);
    assert!(report.timing().is_consistent());
    assert!(report.timing().started().monotonic() >= started.monotonic());
    assert_eq!(report.timing().started().wall_clock(), started.wall_clock());
    assert!(
        report.timing().freshness_marker().monotonic() >= report.timing().started().monotonic()
    );
    assert!(report.validate_exact(&expected).is_ok());

    assert!(matches!(
        Report::committed(expected.len() - 1, expected.clone()).validate_exact(&expected),
        Err(Error::PartialSend {
            expected: 3,
            actual: 2
        })
    ));
    assert!(matches!(
        Report::committed(expected.len(), Bytes::from_static(&[1, 2])).validate_exact(&expected),
        Err(Error::InvalidSendReport {
            bytes_sent: 3,
            wire_bytes: 2
        })
    ));
    assert!(matches!(
        Report::committed(expected.len(), Bytes::from_static(&[3, 2, 1])).validate_exact(&expected),
        Err(Error::InvalidSendEvidence { .. })
    ));
}

#[cfg(not(all(native_layer2, native_layer3)))]
mod missing_layer {
    use packetcraftr_core::error::{Classified, Kind};
    use packetcraftr_netio::{
        NativeCapability, Unsupported,
        transmit::{self, Provider as _},
    };

    use super::*;

    fn send(mode: Mode) -> Error {
        let decision = common::decision(Capability::Layer2AndLayer3);
        let bytes = Bytes::from_static(&[0x45, 0, 0, 20]);
        let outbound = Outbound::try_new(&bytes, route(&decision, mode)).expect("mode is resolved");
        transmit::SystemProvider
            .send(outbound)
            .expect_err("this build has no backend for the layer")
    }

    fn assert_capability_refusal(error: &Error, mode: Mode, operation: &str) {
        assert!(
            matches!(
                error,
                Error::Unsupported(Unsupported {
                    capability: NativeCapability::Transmission(refused),
                    message,
                    source: None,
                }) if *refused == mode && message.contains(operation)
            ),
            "{error:?}"
        );
        let classification = error.classification();
        assert_eq!(classification.code, "capability.unsupported");
        assert_eq!(classification.kind, Kind::Capability);
    }

    #[cfg(not(native_layer2))]
    #[test]
    fn a_build_without_layer2_refuses_a_layer2_frame_with_a_capability_error() {
        assert_capability_refusal(&send(Mode::Layer2), Mode::Layer2, "Layer 2 injection");
    }

    #[cfg(not(native_layer3))]
    #[test]
    fn a_build_without_layer3_refuses_a_layer3_packet_with_a_capability_error() {
        assert_capability_refusal(&send(Mode::Layer3), Mode::Layer3, "raw IP transmission");
    }
}
