// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::{Classification, Classified, Kind, Source};
use thiserror::Error as ThisError;

use crate::link::Mode;

/// A native capability a live operation needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeCapability {
    /// Passive route and interface-route lookups (`native-route`).
    Route,
    /// Interface enumeration (`native-route`).
    InterfaceEnumeration,
    /// Packet capture and its timestamp-type discovery (`native-layer2`).
    Capture,
    /// Transmission in this link mode: Layer 2 injection (`native-layer2`)
    /// or raw IP transmission (`native-layer3`).
    Transmission(Mode),
}

/// A capability that is unavailable: this build or target has no backend for
/// it, or a provider, interface, or device refused it as unsupported.
///
/// This is the one representation of "unsupported" that
/// [`Error`](crate::Error), [`route::SystemError`](crate::route::SystemError),
/// and [`interface::Error`](crate::interface::Error) carry, and its
/// [`capability`](Self::capability) decides its classification:
/// `capability.route` for [`NativeCapability::Route`], and
/// `capability.unsupported` for every other capability.
#[derive(Debug, ThisError, Clone)]
#[error("{} is unavailable: {message}", subject(*.capability))]
pub struct Unsupported {
    pub capability: NativeCapability,
    /// What is missing and, when there is one, the actionable cause.
    pub message: String,
    /// The platform's own refusal, when a native call reported one.
    #[source]
    pub source: Option<Source>,
}

impl Unsupported {
    /// An unsupported `capability` without a platform refusal as its source.
    pub fn new(capability: NativeCapability, message: impl Into<String>) -> Self {
        Self {
            capability,
            message: message.into(),
            source: None,
        }
    }
}

/// What the message says is unavailable; route lookups keep naming the
/// native route selection they need.
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
