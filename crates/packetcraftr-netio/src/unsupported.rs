// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::{Classification, Classified, Kind, Source};
use thiserror::Error as ThisError;

use crate::link::Mode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeCapability {
    Route,
    InterfaceEnumeration,
    Capture,
    Transmission(Mode),
}

impl NativeCapability {
    /// Whether this build carries a native backend for the capability on
    /// this target, answered from build configuration without a native call.
    /// A built capability can still fail at run time, for example without
    /// the privilege to open a capture.
    pub fn check(self) -> Result<(), Unsupported> {
        let (built, enabled, feature, operation) = match self {
            Self::Route => (
                cfg!(native_route),
                cfg!(feature = "native-route"),
                "native-route",
                "route selection",
            ),
            Self::InterfaceEnumeration => (
                cfg!(native_route),
                cfg!(feature = "native-route"),
                "native-route",
                "interface enumeration",
            ),
            Self::Capture => (
                cfg!(native_layer2),
                cfg!(feature = "native-layer2"),
                "native-layer2",
                "packet capture",
            ),
            Self::Transmission(Mode::Layer2) => (
                cfg!(native_layer2),
                cfg!(feature = "native-layer2"),
                "native-layer2",
                "Layer 2 injection",
            ),
            Self::Transmission(Mode::Layer3) => (
                cfg!(native_layer3),
                cfg!(feature = "native-layer3"),
                "native-layer3",
                "raw IP transmission",
            ),
            Self::Transmission(Mode::Auto) => (
                cfg!(native_send),
                cfg!(any(feature = "native-layer2", feature = "native-layer3")),
                "native-layer2 or native-layer3",
                "packet transmission",
            ),
        };
        if built {
            Ok(())
        } else {
            Err(Unsupported::unbuilt(self, enabled, feature, operation))
        }
    }
}

#[derive(Debug, ThisError, Clone)]
#[error("{} is unavailable: {message}", subject(*.capability))]
pub struct Unsupported {
    pub capability: NativeCapability,
    pub message: String,
    #[source]
    pub source: Option<Source>,
}

impl Unsupported {
    /// The failure for a capability this build has no native backend for:
    /// either `feature` is disabled or the target has no backend for it.
    pub(crate) fn unbuilt(
        capability: NativeCapability,
        feature_enabled: bool,
        feature: &str,
        operation: &str,
    ) -> Self {
        Self::new(
            capability,
            if feature_enabled {
                format!("native {operation} is unsupported on this target")
            } else {
                format!("enable the {feature} feature for native {operation}")
            },
        )
    }

    pub fn new(capability: NativeCapability, message: impl Into<String>) -> Self {
        Self {
            capability,
            message: message.into(),
            source: None,
        }
    }
}

const fn subject(capability: NativeCapability) -> &'static str {
    match capability {
        NativeCapability::Route => "native route selection",
        _ => "live packet I/O",
    }
}

impl Classified for Unsupported {
    fn classification(&self) -> Classification {
        match self.capability {
            NativeCapability::Route => Classification::new(
                "capability.route",
                Kind::Capability,
                Some(
                    "enable the native-route capability on a supported target or inject a route provider",
                ),
            ),
            NativeCapability::InterfaceEnumeration
            | NativeCapability::Capture
            | NativeCapability::Transmission(_) => Classification::new(
                "capability.unsupported",
                Kind::Capability,
                Some(
                    "enable and configure the requested native capability; PacketcraftR will not change transmission modes automatically",
                ),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Mode, NativeCapability};

    #[test]
    fn build_checks_follow_the_emitted_capability_cfgs() {
        let cases = [
            (NativeCapability::Route, cfg!(native_route)),
            (NativeCapability::InterfaceEnumeration, cfg!(native_route)),
            (NativeCapability::Capture, cfg!(native_layer2)),
            (
                NativeCapability::Transmission(Mode::Layer2),
                cfg!(native_layer2),
            ),
            (
                NativeCapability::Transmission(Mode::Layer3),
                cfg!(native_layer3),
            ),
            (
                NativeCapability::Transmission(Mode::Auto),
                cfg!(native_send),
            ),
        ];
        for (capability, built) in cases {
            let checked = capability.check();
            assert_eq!(checked.is_ok(), built, "{capability:?}");
            if let Err(error) = checked {
                assert_eq!(error.capability, capability);
            }
        }
    }
}
