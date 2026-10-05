// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(all(native_layer2, native_layer3)))]
mod missing_layer {
    use bytes::Bytes;
    use packetcraftr_core::error::{Classified, Kind};
    use packetcraftr_netio::{
        Error, NativeCapability, Unsupported,
        link::{Capability, Mode},
        transmit::{self, Outbound, Provider as _, Route},
    };

    use crate::common;

    fn send(mode: Mode) -> Error {
        let decision = common::decision(Capability::Layer2AndLayer3);
        let bytes = Bytes::from_static(&[0x45, 0, 0, 20]);
        let route = Route {
            decision: &decision,
            mode,
            lookup_destination: Some(common::lookup_destination()),
        };
        let outbound = Outbound::try_new(&bytes, route).expect("mode is resolved");
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
